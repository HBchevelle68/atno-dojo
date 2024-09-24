#ifndef STUDENT_LOADER_H
#define STUDENT_LOADER_H

#define ADDR_ZERO_THEN_DONE \
    do                      \
    {                       \
        addr = 0;           \
        goto done;          \
    } while (0)

#define FREE_IF_VALID(ptr) \
    do                     \
    {                      \
        if (NULL != ptr)   \
        {                  \
            free(ptr);     \
            ptr = NULL;    \
        }                  \
    } while (0)

#define IF_NULL_ERROR_THEN_DONE(ptr) \
    do                               \
    {                                \
        if (NULL == ptr)             \
        {                            \
            result = 1;              \
            goto done;               \
        }                            \
    } while (0)

#endif

uint64_t student_load(uint8_t *fdata, size_t size);
void student_jump(uint64_t entry);