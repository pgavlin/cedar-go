#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

enum Severity {
  None,
  Advice,
  Warning,
  Error,
};
typedef uint8_t Severity;

typedef struct RawString {
  uint8_t *ptr;
  uintptr_t len;
  uintptr_t cap;
} RawString;

typedef struct RawStrings {
  struct RawString *ptr;
  uintptr_t len;
  uintptr_t cap;
} RawStrings;

typedef struct LabeledSpan {
  struct RawString text;
  uintptr_t offset;
  uintptr_t len;
} LabeledSpan;

typedef struct Labels {
  struct LabeledSpan *ptr;
  uintptr_t len;
  uintptr_t cap;
} Labels;

typedef struct Diagnostic {
  struct RawString code;
  struct Labels labels;
  Severity severity;
  struct RawString help;
  struct RawString url;
} Diagnostic;

typedef struct Diagnostics {
  struct Diagnostic *ptr;
  uintptr_t len;
  uintptr_t cap;
} Diagnostics;

typedef struct PolicySet {
  struct PolicySet *ptr;
} PolicySet;

typedef struct Schema {
  struct Schema *ptr;
} Schema;

typedef struct Validator {
  struct Validator *ptr;
} Validator;

typedef struct Authorizer {
  struct Authorizer *ptr;
} Authorizer;

typedef struct Decision {
  bool allow;
  struct RawStrings reasons;
} Decision;

void free_string(struct RawString s);

void free_raw_strings(struct RawStrings b);

void free_labels(struct Labels b);

void free_diagnostics(struct Diagnostics b);

void free_policy_set(struct PolicySet b);

struct Diagnostics parse_policies(const char *input, struct PolicySet *policy_set);

void free_schema(struct Schema b);

struct Diagnostics parse_schema(const char *input, struct Schema *s);

void free_validator(struct Validator b);

struct Validator new_validator(struct Schema s);

struct Diagnostics validate(struct Validator validator, struct PolicySet policy_set);

void free_authorizer(struct Authorizer b);

struct Authorizer new_authorizer(void);

struct Diagnostics is_authorized(struct Authorizer a,
                                 const char *request_json,
                                 struct PolicySet p,
                                 struct Schema s,
                                 struct Decision *decision);

struct RawString json_is_authorized(const char *input);
