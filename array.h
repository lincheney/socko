#define ARRAY_TYPE(NAME, TYPE, KEY_TYPE, CMP_FN) \
    typedef struct { \
        size_t length; \
        size_t capacity; \
        TYPE* data; \
    } NAME; \
     \
    int NAME ## _find(NAME* array, const KEY_TYPE key) { \
        for (int i = 0; i < array->length; i++) { \
            if (CMP_FN(key, array->data[i])) { \
                return i; \
            } \
        } \
        return -1; \
    } \
     \
    int NAME ## _append(NAME* array, TYPE value) { \
        if (array->length >= array->capacity) { \
            if (array->capacity == 0) { \
                array->capacity = 4; \
            } else { \
                array->capacity *= 2; \
            } \
            array->data = realloc(array->data, array->capacity*sizeof(TYPE)); \
        } \
        array->data[array->length] = value; \
        array->length += 1; \
        return array->length-1; \
    } \
    void NAME ## _delete(NAME* array, int index) { \
        if (array->length > 1) { \
            array->data[index] = array->data[array->length-1]; \
        } \
        array->length--; \
    } \

