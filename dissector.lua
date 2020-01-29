package.path = package.path .. ";./lockbox/?.lua"

local String = require("string");

local Array = require("lockbox.util.array");
local Stream = require("lockbox.util.stream");

local CBCMode = require("lockbox.cipher.mode.cbc");

local PKCS7Padding = require("lockbox.padding.pkcs7");
local ZeroPadding = require("lockbox.padding.zero");

local AES256Cipher = require("lockbox.cipher.aes256");


validity90_proto = Proto("validity90", "Validity 90 fingerprint reader protocol")

local f = validity90_proto.fields
f.f_magic_header = ProtoField.uint24("validity90.magic", "Magic Header", base.HEX)
f.f_length = ProtoField.uint16("validity90.length", "Packet length bytes", base.DEC)
f.f_iv = ProtoField.bytes("validity90.iv", "Encryption AES IV")
f.f_data = ProtoField.bytes("validity90.data", "Encrypted data")
f.f_dec_data = ProtoField.bytes("validity90.dec_data", "Decrypted data")
f.f_particial = ProtoField.bool("validity90.partial", "Is partial", base.NONE, {[1] = "no", [2] = "yes"})

local f_direction = Field.new("usb.endpoint_address.direction")

local CONST_MAGIC_HEADER_RSP_6 = ByteArray.new("0000001000000000")
local CONST_MAGIC_HEADER_44 = ByteArray.new("44000000")
local CONST_MAGIC_HEADER = ByteArray.new("170303")
local CONST_MAGIC_HEADER_TLS_DATA = ByteArray.new("17")
local CONST_MAGIC_HEADER_TLS = ByteArray.new("16")
local CONST_MAGIC_HEADER_TLS15 = ByteArray.new("15")
local CONST_MAGIC_HEADER_TLS14 = ByteArray.new("14")

local packetDb = {}
local partialBuffer = nil

local major, minor, micro = "0", "0", "0"
if get_version then
    major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
end

if tonumber(major) < 3 then
    local sslDissector = Dissector.get('ssl')
else
    local sslDissector = Dissector.get('tls')
end

local function decode_aes(ivStr, dataStr)
    -- body
    local decipher = CBCMode.Decipher()
    
    local key = nil
    local dir = f_direction()
    
    if tostring(f_direction()) == "1" then
        key = Array.fromHex(validity90_proto.prefs["aes_in"])
    else
        key = Array.fromHex(validity90_proto.prefs["aes_out"])
    end

    local iv = Array.fromHex(ivStr)
    local ciphertext = Array.fromHex(dataStr)
    decipher
            .setKey(key)
            .setBlockCipher(AES256Cipher)
            .setPadding(PKCS7Padding);

    local plainOutput = decipher
                        .init()
                        .update(Stream.fromArray(iv))
                        .update(Stream.fromArray(ciphertext))
                        .finish()
                        .asHex();

    return plainOutput
end

function parseSsl(buffer, pinfo, tree)
    sslDissector:call(buffer, pinfo, tree)
end

function resp_6_type_to_string(type)
    if type == 3 then
        return "RSP6_TLS_CERT"
    elseif type == 4 then
        return "RSP6_ECDSA_PRIV_ENCRYPTED"
    elseif type == 6 then
        return "RSP6_ECDH_PUB"
    else
        return "Unknown"
    end
end

function validity90_proto.dissector(buffer, pinfo, tree)
    local buf = nil

    if packetDb[pinfo.number] == nil or packetDb[pinfo.number].buf == nil then
        packetDb[pinfo.number] = {};

        if partialBuffer == nil then
            partialBuffer = buffer:bytes()
            buf = partialBuffer:tvb("New joint packet")
        else
            partialBuffer:append(buffer:bytes())
            buf = partialBuffer:tvb("Joint packet")
        end
    else
        local state = packetDb[pinfo.number]

        buf = state.buf:tvb("Joint packet [loaded]")
    end

    -- buf = buffer:bytes():tvb("Joint packet")
    -- buf = buffer

    pinfo.cols["protocol"] = "Validity90"

    -- create protocol tree
    local t_validity90 = tree:add(validity90_proto, buf())
    local offset = 0

    -- pinfo.cols["src"] = 'CLIENT'
    -- pinfo.cols["dst"] = 'SERVER'
    -- pinfo.cols["port_type"] = "2"
    -- pinfo.cols["src_port"] = "0"
    -- pinfo.cols["dst_port"] = "443"
    

    -- Header
    local magic_header
    local magic_header4
    local magic_header1

    if (buf:len() > 2) then
        magic_header = buf(offset, 3)
    end

    if (buf:len() > 3) then
        magic_header4 = buf(offset, 4)
    end

    if (buf:len() > 0) then
        magic_header1 = buf(offset, 1)
    end

    if buf:len() > 8 and buf(offset, 8):bytes() == CONST_MAGIC_HEADER_RSP_6 then
        pinfo.cols["info"]:append(" Validity 94 - Response 6")

        local resp6_type
        local resp6_len
        local resp6_hash
        local resp6_offset = 8

        resp6_type = buf(resp6_offset, 2):le_uint()
        resp6_len = buf(resp6_offset + 2, 2):le_uint()
        resp6_hash = buf(resp6_offset + 4, 32)
        while( resp6_type ~= 65535 )
        do

            local t_resp6_packet_tree = t_validity90:add(buf(resp6_offset, 4 + 32 + resp6_len), "Response 6 Packet", resp_6_type_to_string(resp6_type))
            t_resp6_packet_tree:add(buf(resp6_offset, 2), "Type", resp6_type)
            t_resp6_packet_tree:add(buf(resp6_offset + 2, 2), "Length", resp6_len)
            t_resp6_packet_tree:add(buf(resp6_offset + 4, 32), "Hash", tostring(resp6_hash))
            t_resp6_packet_tree:add(buf(resp6_offset + 4 + 32, resp6_len), "Content", tostring(buf(resp6_offset + 4 + 32, resp6_len)))

            resp6_offset = resp6_offset + 4 + 32 + resp6_len
            resp6_type = buf(resp6_offset, 2):le_uint()
            resp6_len = buf(resp6_offset + 2, 2):le_uint()
            resp6_hash = buf(resp6_offset + 4, 32)
        end
    end

    if magic_header1 and magic_header1:bytes() == CONST_MAGIC_HEADER_TLS 
        or magic_header1:bytes() == CONST_MAGIC_HEADER_TLS_DATA 
        or magic_header1:bytes() == CONST_MAGIC_HEADER_TLS14
        or magic_header1:bytes() == CONST_MAGIC_HEADER_TLS15
        then
        offset = offset + 3

        pcall(parseSsl, buf, pinfo, tree)

        if magic_header and magic_header:bytes() == CONST_MAGIC_HEADER then
            t_validity90:add(f.f_magic_header, magic_header)

            -- Len
            local len = buf(offset, 2)
            offset = offset + 2
            t_validity90:add(f.f_length, len)
            
            if buf:len() - 5 < len:uint() then
                pinfo.cols["info"]:append(string.format(" INCOMPLETE %d left", len:uint() - buf:len() + 5))
                t_validity90:add(f.f_particial, false)
            elseif buf:len() - 5 == len:uint() then
                pinfo.cols["info"]:append(string.format(" COMPLETED", len:uint() - buf:len() + 5))
                partialBuffer = nil

                t_validity90:add(f.f_particial, true)

                -- iv
                local iv = buf(offset, 16)
                offset = offset + 16
                t_validity90:add(f.f_iv, iv)

                -- Raw Data
                local data = buf(offset)
                t_validity90:add(f.f_data, data)

                -- Decode
                local dec_data = ByteArray.new(decode_aes(iv:bytes():tohex(), data:bytes():tohex()))
                local res = dec_data:tvb("Decrypted")

                local pad_len = dec_data:get_index(dec_data:len() - 1) + 1
                dec_data:subset(0, dec_data:len() - 0x20 - pad_len):tvb("Unpadded")

                t_validity90:add(f.f_dec_data, res())
            else
                pinfo.cols["info"]:append(string.format(" INVALID", len:uint() - buf:len() + 5))
                partialBuffer = nil
            end
        else
            t_validity90:add(f.f_magic_header, magic_header)
            -- pinfo.cols["info"]:append(string.format(" Invalid header %#03x", magic_header:le_uint()))        

            partialBuffer = nil
        end

        packetDb[pinfo.number].buf = buf:bytes()
    elseif magic_header4 and magic_header4:bytes() == CONST_MAGIC_HEADER_44 then
        offset = offset + 4
        partialBuffer = nil
        pcall(parseSsl, buf:bytes(offset):tvb("44 data"), pinfo, tree)
    else
        partialBuffer = nil
    end
end


-- preferences
validity90_proto.prefs["aes_in"] = Pref.string("IN AES Key", "", "")
validity90_proto.prefs["aes_out"] = Pref.string("OUT AES Key", "", "")


usb_table = DissectorTable.get("usb.bulk")
usb_table:add(0xFF, validity90_proto)
usb_table:add(0xFFFF, validity90_proto)
