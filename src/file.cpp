#include "file.h"

ErrorOr<char*> readFile(const char* path, size_t& length)
{
    FILE* file = fopen(path, "rb");
    if(file == nullptr) {
        return {{"Failed to open file ("+std::string(path)+")"}};
    }
    fseek(file, 0, SEEK_END);
    length = (size_t)ftell(file);
    fseek(file, 0, SEEK_SET);
    char* data = (char*)malloc(length);
    if(data == nullptr) {
        fclose(file);
        return {{"Failed allocate ("+std::to_string(length)+" bytes) for file ("+std::string(path)+")"}};
    }
    size_t rlength = fread(data, length, 1, file);
    if(rlength != 1) {
        free(data);
        fclose(file);
        return {{"Failed to read whole file ("+std::string(path)+")"}};
    }
    fclose(file);
    return data;
};

ErrorOr<void> writeFile(const char* path, const char* data, size_t length)
{
    FILE* file = fopen(path, "wb");
    if(file == nullptr) {
        return {{"Failed to open file ("+std::string(path)+")"}};
    }
    size_t slength = fwrite(data, length, 1, file);
    if(slength != 1) {
        fclose(file);
        return {{"Failed to write whole file ("+std::string(path)+")"}};
    }
    fclose(file);
    
    return {};
}