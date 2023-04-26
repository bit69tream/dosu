#define _GNU_SOURCE

#include <bsd/readpassphrase.h>
#include <crypt.h>
#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char* concat(char *input1, char *input2) {
  char *out = malloc(strlen(input1) + strlen(input2) + 2);
  strcpy(out, input1);
  strcat(out, input2);
  return out;
}

char *get_original_salt(const char *crypted_password) {
  static char salt[21] = {0};
  memset(salt, 0, sizeof(salt) / sizeof(char));

  unsigned int salt_end = 0, dollar_count = 0;
  for (; crypted_password[salt_end] != 0 && dollar_count < 3; salt_end++) {
    if (crypted_password[salt_end] == '$') {
      dollar_count++;
    }
  }
  strncpy(salt, crypted_password, salt_end - 1);

  return salt;
}

int main(int argc, char **argv) {
  if (argc < 2)
    return 1;

  struct passwd *current_user_password_entry = getpwuid(getuid());
  if (current_user_password_entry == NULL) {
    perror("ERROR: getpwuid");
    return 1;
  }

  struct spwd *current_user_shadow_entry = getspnam(current_user_password_entry->pw_name);
  if (current_user_shadow_entry == NULL) {
    perror("ERROR: getspnam");
    return 1;
  }

  static char password_buffer[1024] = {0};
  memset(password_buffer, 0, sizeof(password_buffer) / sizeof(char));

  char *input = readpassphrase("password: ", password_buffer, sizeof(password_buffer) / sizeof(char), RPP_ECHO_OFF | RPP_REQUIRE_TTY);
  if (input == NULL) {
    perror("ERROR: readpassphrase");
    return 1;
  }

  char *crypted_input = crypt(input, get_original_salt(current_user_shadow_entry->sp_pwdp));
  if (strcmp(current_user_shadow_entry->sp_pwdp, crypted_input) != 0) {
    fprintf(stderr, "ERROR: Invalid password\n");
    return 1;
  }

  struct passwd *root_pw = getpwuid(0);
  if (root_pw == NULL) {
    perror("ERROR: getpwuid");
    return 1;
  }

  if (setuid(root_pw->pw_uid)) {
    perror("ERROR: setuid");
    return 1;
  }
  if (setgid(root_pw->pw_gid)) {
    perror("ERROR: setgid");
    return 1;
  }

  char *envp[] = {
    concat("PATH=", getenv("PATH")),
    concat("TERM=", getenv("TERM")),
    concat("USER=", root_pw->pw_name),
    concat("SHELL=", root_pw->pw_shell),
    concat("LOGNAME=", root_pw->pw_name),
    concat("HOME=", root_pw->pw_dir),
    NULL,
  };

  if (execvpe(argv[1], argv + 1, envp) == -1) {
    perror("ERROR: execvpe");
    return 1;
  }

  return 0;
}
