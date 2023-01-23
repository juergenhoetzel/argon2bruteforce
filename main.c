#include <argon2.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <threads.h>
#include <unistd.h>

void usage() {
  fprintf(stderr, "Usage: argon2bruteforce <HASH> \n");
  fprintf(stderr, "Bruteforce words on STDIN\n\n"
                  "  -t\t n_threads\n"
                  "  -v\t verbose output\n");
}

typedef struct work_t {
  _Atomic int finished;
  int thread_num;
  const char *hash;
} work_t;

int verify_words(void *arg) {
  work_t *p_work = (work_t *)arg;
  size_t max_len = 0;
  char *line = NULL;
  int n;
  int type;
  if (strncmp(p_work->hash, "$argon2id$", 10) == 0)
    type = Argon2_id;
  else if (strncmp(p_work->hash, "$argon2i$", 9) == 0)
    type = Argon2_i;
  else if (strncmp(p_work->hash, "$argon2d$", 9) == 0)
    type = Argon2_d;
  else {
    fprintf(stderr, "Invalid Hash: %s\n", p_work->hash);
    return 0;
  }
  while (p_work->finished == 0 && (n = getline(&line, &max_len, stdin)) != -1) {
    line[n - 1] = 0; /* remove newline */
    int r = argon2_verify(p_work->hash, line, n - 1, type);
    if (r == ARGON2_OK) {
      printf("Found: %s\n", line);
      free(line);
      fclose(stdin);
      p_work->finished++;
      return 1;
    }
    if (r != ARGON2_VERIFY_MISMATCH) {
      fprintf(stderr, "argon2_verify(%s, %s) failed: %s\n", p_work->hash, line, argon2_error_message(r));
    }
  }
  p_work->finished++;
  free(line);
  return 0;
}

int main(int argc, char *argv[]) {
  work_t work = {.finished = 0, .hash = NULL};
  int c;
  int n_threads = 1;
  bool verbose = false;
  while ((c = getopt(argc, argv, "hvt:")) != -1) {
    switch (c) {
    case 'h':
      usage();
      return 1;
    case 'v':
      verbose = true;
      break;
    case 't':
      n_threads = atoi(optarg);
      break;
    }
  }
  struct stat statbuf;
  if (fstat(0, &statbuf) < 0) {
    perror("fstat stdin");
    return 1;
  }
  if (!statbuf.st_size && verbose) {
    fprintf(stderr, "Can't use verbose on unkown input file size\n");
    verbose = 1;
  }

  if (argc - optind != 1) {
    usage();
    return 1;
  }
  work.hash = argv[optind];

  thrd_t *thrds = malloc(sizeof(thrd_t) * n_threads);

  for (int i = 0; i < n_threads; i++) {
    thrd_create(&thrds[i], verify_words, &work);
  }
  time_t start = time(NULL);

  while (!work.finished) {
    if (verbose) {
      float p = ftell(stdin) * 100. / statbuf.st_size;
      time_t passed_seconds = time(NULL) - start;
      float eta = passed_seconds / p * 100;
      printf("Progress (ETA: %.1f sec): %.2f%%\n", eta, p);
    }
    thrd_sleep(&(struct timespec){.tv_sec = 1}, NULL); // sleep 1 sec
  }
  for (int i = 0; i < n_threads; i++) {
    thrd_join(thrds[i], NULL);
  }

  return 0;
}
