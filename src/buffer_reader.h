#pragma once
#include "error.h"
#include <stdint.h>
#include <string>

struct BufferReader {
    const uint8_t* start;
    size_t len;
    size_t pos;

    BufferReader(const uint8_t* start, size_t len) :
        start(start),
        len(len),
        pos(0)
    {};

    ErrorOr<uint8_t*> ReadRaw(size_t readlen) {
        uint8_t* data = (uint8_t*)(start + pos);
        pos += readlen;
        if(pos > len) return {{"Not enough data to read value"}};
        return data;
    }

    template<typename T>
    ErrorOr<T> Read() {
        return *(T*)TRY(ReadRaw(sizeof(T)));
    }

    template<typename T>
    ErrorOr<T> ReadVarInt(size_t length) {
        T temp = 0;
        for(int i=0; i<length; ++i) {
            temp |= TRY(Read<uint8_t>()) << (i*8);
        }
        return temp;
    }

    ErrorOr<std::string> ReadCString() {
        const uint8_t* startPos = start + pos;
        while(*TRY(ReadRaw(1)) == 0);
        std::string str((const char*)startPos, (start + pos) - startPos);
        return str;
    }

    template<typename T>
    ErrorOr<T> parseULEB128() {
        T result = 0;
        uint8_t shift = 0;
        size_t i=0;
        while (true) {
            uint8_t byte = TRY(Read<uint8_t>());
            result |= (T)(byte & 0x7f) << shift;
            if ((byte & 0x80) == 0)
                break;
            shift += 7;
        }
        return result;
    }

    template<typename T>
    ErrorOr<T> parseLEB128() {
        T result = 0;
        uint8_t shift = 0;
        size_t size = sizeof(T)*8;
        uint8_t byte;
        do {
            byte = TRY(Read<uint8_t>());
            result |= (T)(byte & 0x7f) << shift;
            shift += 7;
        } while ((byte & 0x80) != 0);
        
        if ((shift < size) && (byte & 0x40)) {
            result |= (~0 << shift);
        }
        
        return result;
    }
};