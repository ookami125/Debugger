#pragma once

#include <string>
#include <assert.h>

#define TRY(x) ({ auto ev = (x); if(!ev.ok()) return ev.error(); ev.value(); })
#define CATCH(x, y) ({ auto ev = (x); if(!ev.ok()) y; ev.value(); })

struct Error {
    std::string msg;
};

template<typename T>
struct ErrorOr {
    enum Tag {
        ERROR,
        VALUE,
    } tag;
    union {
        Error* u_error;
        T u_value;
    };

    ~ErrorOr() {
        if(tag == ERROR) {
            delete u_error;
        }
    }

    ErrorOr(Error _error) :
        tag(ERROR),
        u_error(new Error(_error))
    {}

    ErrorOr(T _value) :
        tag(VALUE),
        u_value(_value)
    {}

    bool ok() {
        return tag == VALUE;
    }

    T value() {
        assert(tag == VALUE);
        return u_value;
    }

    Error error() {
        assert(tag == ERROR);
        return *u_error;
    }
};

template<>
struct ErrorOr<void> {
    enum Tag {
        ERROR,
        VOID,
    } tag;
    Error* u_error;
    
    ~ErrorOr() {
        if(tag == ERROR) {
            delete u_error;
        }
    }
    
    ErrorOr() :
        tag(VOID),
        u_error(nullptr)
    {}

    ErrorOr(Error _error) :
        tag(ERROR),
        u_error(new Error(_error))
    {}

    bool ok() {
        return tag == VOID;
    }

    void value() {
        assert(tag == VOID);
    }

    Error error() {
        assert(tag == ERROR);
        return *u_error;
    }
};