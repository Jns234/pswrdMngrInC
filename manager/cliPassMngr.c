#include <stdio.h>
#include <sqlite3.h>
#include <string.h>
#include <stdint.h>
#include <sodium.h>
#include <unistd.h>
#include <ctype.h>  
#include <stdlib.h> 
#include <time.h>
#include <pwd.h>
#include <limits.h>
#include <termios.h>

#define SQL_FILE "test.db"
#define SQLITE_HAS_CODEC 1
#define KEY_BYTES crypto_secretbox_KEYBYTES
#define LOG_FILE "test-log.log"
#define MAXPW 32

#define SAVED_PASSWORD_LEN 160

static const unsigned char SALT[crypto_pwhash_SALTBYTES] = {
    0xC1, 0x2B, 0x5F, 0xED,
    0x66, 0x00, 0x52, 0x14,
    0x80, 0x4E, 0xA6, 0x93,
    0x4B, 0x1C, 0x52, 0xC6
};

// URL encode/decode declarations
char from_hex(char ch);
char to_hex(char code);
char *url_encode(char *str);
char *url_decode(char *str);

// Declaring the pointer for the sqlite db
sqlite3 *db;
sqlite3_stmt *stmt = NULL;

unsigned char MasterKey[KEY_BYTES];
int i;

// Need to declare functions
int init_db();
int add_pass(char* Account, char* Site, char* Password);
int list_pass();
int handle_pass_insert();
int handle_read();
int handle_edit();
int handle_delete();
int delete_password(int id);
int edit(int id, const char *newPassword);
int read_password(int *Id);
int check_db();
int first_db_init();
int request_password(char *out, size_t out_size);
int set_master_key(const char *MasterPassword);
int encrypt(const unsigned char *password, unsigned long long password_len,
            const unsigned char *key,
            unsigned char *nonce_out,
            unsigned char *cipher_out);
int decrypt(unsigned char *decrypted_password,
            const unsigned char *ciphertext, unsigned long long ciphertext_len,
            const unsigned char *nonce,
            const unsigned char *key);
ssize_t getpasswd (char **pw, size_t sz, int mask, FILE *fp);

typedef struct StoredPassword {
  int Id;
  const unsigned char *Site;
  const unsigned char *Account;
} StoredPassword;

void log_events(char *event, char *outcome, char *message)
{
    FILE* log_file = fopen(LOG_FILE , "a");
    time_t timestamp = time(NULL);
    struct tm *t = localtime(&timestamp);
    char buffer[100];
    struct passwd *p=getpwuid(getuid());
    char *username=p?p->pw_name:0;
    char hostname[1024];
    hostname[1023] = '\0';

    gethostname(hostname, 1023);
    strftime(buffer, sizeof(buffer), "%d-%m-%Y %H:%M:%S", t);

    fprintf(log_file, "%s - %s - %s - %s - %s - %s\n",
            buffer,
            username,
            hostname,
            event,
            outcome,
            message);

    fclose(log_file);
}


void dump_hex_buff(const unsigned char buf[], unsigned int len)
{
    for (unsigned int i = 0; i < len; i++) {
        printf("%02X ", buf[i]);
    }
    printf("\n");
}


int callback(void *NotUsed, int argc, char **argv, char **azColName)  {
    (void)NotUsed;

    for (int i = 0; i < argc; i++){
        const char *name = azColName[i];
        char *val = argv[i];

        if (val && (strcmp(name, "Site") == 0 || strcmp(name, "Account") == 0)) {
            char *decoded = url_decode(val);
            printf("%s = %s\n", name, decoded ? decoded : "NULL");
            if (decoded) free(decoded);
        } else {
            printf("%s = %s\n", name, val ? val : "NULL");
        }
    }
    printf("\n");

    return 0;
}

int main()
{   
    typedef enum commands {
        save = 0,
        list,
        read,
        edit,
        delete
    } CMND;
    printf("\033[H\033[J");
    if (sodium_init() < 0) {
        log_events("Sodium", "failure", "Libsodium has failed");
        return 1;
    }

    if (init_db() != 0) {
        log_events("Database", "failure", "Failed to start the database");
        return 1;
    }
    log_events("program_start", "success", "The programm has started");
    printf("\033[H\033[J");
Start:
    int command;

    printf("This is the CLI Password Manager prototype!\n");

    printf("Here are your options:\n\t0 - Save a password\n\t1 - List possible passwords\n\t2 - Read a password\n\t3 - Edit a password\n\t4 - Delete a password\n");

    printf("Waiting for a command\n");

    if (scanf("%d", &command) != 1) {
        printf("Invalid input\n");
        return 1;
    }

    printf("Your command: %d\n", command);

    CMND cmdn = command;

    switch (cmdn)
    {
    case save:
        printf("You chose to save\n");
        log_events("program", "notify", "Password save initiated");
        handle_pass_insert();
        goto Start;
    case list:
        printf("You chose to list\n");
        log_events("program", "notify", "Password listing initiated");
        list_pass();
        goto Start;
    case read:
        handle_read();
        log_events("program", "notify", "Password read initiated");
        goto Start;
    case edit:
        printf("You chose to edit\n");
        log_events("program", "notify", "Password edit initiated");
        handle_edit();
        goto Start;    
    case delete:
        printf("You chose to delete!\n");
        log_events("program", "notify", "Password dletion initiated");
        handle_delete();
        goto Start;
    default:
        break;
    }
    sqlite3_close(db);
    return 0;
}

int init_db()
{   
    char MasterPassword[20];

    if (check_db() != 0) {
        printf("No database file present\n");
        log_events("database", "notify", "Database creation started");
        if (first_db_init() != 0) {
            log_events("database", "error", "Database creation failed");
            return 1;
        } 
        return 0;
    }

    if (request_password(MasterPassword, sizeof MasterPassword) != 0) {
        log_events("database", "error", "Database password failure");
        return 1;
    }

    if (set_master_key(MasterPassword) != 0){
        log_events("database", "error", "Database password failure");
        return 1;
    }

    int response_code = sqlite3_open(SQL_FILE, &db);

    if (response_code != SQLITE_OK) {
        log_events("database", "error", "Error in the database");
        sqlite3_close(db);
        return 1;
    }

    response_code = sqlite3_key(db, MasterPassword, (int)strlen(MasterPassword));
    
    if(response_code != SQLITE_OK){
        log_events("database", "error", "Database failure");
        return 1;
    }
    log_events("database", "notify", "Database creation finished");
    
    return 0;
}

int check_db()
{
    if (access(SQL_FILE, F_OK) == 0) {
        return 0;
    } else {
        return 1;
    }
}

int first_db_init()
{
    char MasterPassword[20];

    if (request_password(MasterPassword, sizeof MasterPassword) != 0) {
        log_events("database", "error", "Database password error");
        return 1;
    }
    if (set_master_key(MasterPassword) != 0){
        log_events("database", "error", "Database password error");
        return 1;
    }

    char *err_msg  = 0;
    int response_code = sqlite3_open(SQL_FILE, &db);

    if (response_code != SQLITE_OK) {
        log_events("database", "error", "Error in the database");
        sqlite3_close(db);
        return 1;
    }

    response_code = sqlite3_key(db, MasterPassword, (int)strlen(MasterPassword));
    
    if(response_code != SQLITE_OK){
        log_events("database", "error", "Database  error");
        return 1;
    }

    char *sql =
        "CREATE TABLE IF NOT EXISTS Passwords("
        "Id INTEGER PRIMARY KEY,"
        "Account TEXT,"
        "Site TEXT,"
        "Password TEXT,"
        "Nonce BLOB,"
        "Ciphertext BLOB);";

    response_code = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (response_code != SQLITE_OK) {
        log_events("database", "error", "Error in the database");
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 1;
    }
    log_events("database", "notify", "Database creation finished");
    return 0;
}

int request_password(char *out, size_t out_size)
{
    char pw[MAXPW] = {0};
    char *p = pw;
    FILE *fp = stdin;

    printf("Please enter your master password:\n");
    getpasswd(&p, MAXPW, '*', fp);

    int len = (int)strlen(p);

    if ((size_t)len >= out_size) {
        log_events("program", "error", "Password error");
        return 1;
    }

    memcpy(out, p, len);
    out[len] = '\0';

    return 0;
}

int handle_pass_insert() {
    char Account[30];
    char Site[40];
    char Password[50];

    printf("You've chosen to add a password!\n");

    printf("Please enter the email/account you wish to add:\n");
    if (scanf("%29s", Account) != 1) {
        printf("Invalid input\n");
        return 1;
    }

    printf("Please enter the site you wish to add:\n");
    if (scanf("%39s", Site) != 1) {
        printf("Invalid input\n");
        return 1;
    }

    printf("Please enter the password you wish to add:\n");
    if (scanf("%49s", Password) != 1) {
        printf("Invalid input\n");
        return 1;
    }

    printf("Here's what you will add: %s, %s, %s \n", Account, Site, Password);
    
    add_pass(Account, Site, Password);

    return 0;
}

int add_pass(char *Account, char *Site, char *Password) 
{
    char *err_msg = 0;
    char *sql =
        "INSERT INTO Passwords(Account, Site, Password, Nonce, Ciphertext)"
        " VALUES(?, ?, ?, ?, ?);";

    char *encodedAccount  = url_encode(Account);
    char *encodedSite     = url_encode(Site);
    char *encodedPassword = url_encode(Password);
    if (!encodedAccount || !encodedSite || !encodedPassword) {
        log_events("program", "error", "Password error");
        if (encodedAccount)  free(encodedAccount);
        if (encodedSite)     free(encodedSite);
        if (encodedPassword) free(encodedPassword);
        return 1;
    }

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    size_t plaintext_len = strlen(encodedPassword); 
    size_t ciphertext_len = crypto_secretbox_MACBYTES + plaintext_len;
    unsigned char ciphertext[ciphertext_len];

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_free(err_msg);
        log_events("program", "error", "Error in the database");
        sqlite3_close(db);
        free(encodedAccount);
        free(encodedSite);
        free(encodedPassword);
        return 1;
    }

    if (encrypt((const unsigned char *)encodedPassword, (unsigned long long)plaintext_len,
                MasterKey, nonce, ciphertext) != 0) {
        sqlite3_finalize(stmt);
        log_events("program", "error", "Encryption error");
        free(encodedAccount);
        free(encodedSite);
        free(encodedPassword);
        return 1;
    }

    sqlite3_bind_text(stmt, 1, encodedAccount,  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, encodedSite,     -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, encodedPassword, -1, SQLITE_TRANSIENT); 
    sqlite3_bind_blob(stmt, 4, nonce, crypto_secretbox_NONCEBYTES, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 5, ciphertext, (int)ciphertext_len, SQLITE_TRANSIENT);
 
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        log_events("program", "error", "Error in the database");
        return 1;
    }
    sqlite3_finalize(stmt);

    free(encodedAccount);
    free(encodedSite);
    free(encodedPassword);

    return rc == SQLITE_DONE ? 0 : 1;
}

int set_master_key(const char *MasterPassword)
{
    if (crypto_pwhash(MasterKey, sizeof MasterKey,
                      MasterPassword, strlen(MasterPassword),
                      SALT,
                      crypto_pwhash_OPSLIMIT_SENSITIVE,
                      crypto_pwhash_MEMLIMIT_SENSITIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        return 1;
    }
    return 0;
}

int encrypt(const unsigned char *password, unsigned long long password_len,
            const unsigned char *key,
            unsigned char *nonce_out,
            unsigned char *cipher_out)
{
    randombytes_buf(nonce_out, crypto_secretbox_NONCEBYTES);

    if (crypto_secretbox_easy(cipher_out,
                              password,
                              password_len,
                              nonce_out,
                              key) != 0) {
        return 1;
    }
    return 0;
}

int decrypt(unsigned char *decrypted_password,
            const unsigned char *ciphertext, unsigned long long ciphertext_len,
            const unsigned char *nonce,
            const unsigned char *key)
{
    if (crypto_secretbox_open_easy(decrypted_password,
                                   ciphertext,
                                   ciphertext_len,
                                   nonce,
                                   key) != 0) {
        return 1;
    }
    return 0;
}

int read_password(int* Id)
{
    unsigned char decrypted_password[SAVED_PASSWORD_LEN];

    char *err_msg = 0;
    char *sql =
        "SELECT Id, Account, Site, Password, Nonce, Ciphertext "
        "FROM Passwords WHERE Id == ?;";

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        log_events("program", "error", "Error in the database");
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 1;
    }

    rc = sqlite3_bind_int(stmt, 1, *Id);
    if (rc != SQLITE_OK) {
        log_events("program", "error", "Error in the database");
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 1;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const unsigned char *nonce = sqlite3_column_blob(stmt, 4);
        unsigned int nonce_len = sqlite3_column_bytes(stmt, 4);

        const unsigned char *ciphertext = sqlite3_column_blob(stmt, 5);
        unsigned int ciphertext_len = sqlite3_column_bytes(stmt, 5);

        if (nonce_len != crypto_secretbox_NONCEBYTES) {
            log_events("program", "error",  "Stored nonce has invalid length");
            sqlite3_finalize(stmt);
            return 1;
        }

        if (ciphertext_len <= crypto_secretbox_MACBYTES ||
            ciphertext_len - crypto_secretbox_MACBYTES > SAVED_PASSWORD_LEN - 1) {
            log_events("program", "error",  "Stored ciphertext length invalid");
            sqlite3_finalize(stmt);
            return 1;
        }

        if (decrypt(decrypted_password,
                    ciphertext, (unsigned long long)ciphertext_len,
                    nonce, MasterKey) != 0) {
            log_events("program", "error",  "Decryption failed (wrong key/corrupt data)");
            sqlite3_finalize(stmt);
            return 1;
        }

        int plaintext_len = ciphertext_len - crypto_secretbox_MACBYTES;
        decrypted_password[plaintext_len] = '\0';

        char *decodedPassword = url_decode((char *)decrypted_password);

        printf("Password: %s\n", decodedPassword);
        printf("Press ENTER when you are done viewing.\n");

        int c;
        while ((c = getchar()) != '\n' && c != EOF) {} 
        getchar();

        printf("\033[H\033[J");
        sodium_memzero(decrypted_password, sizeof decodedPassword);

        if (decodedPassword) free(decodedPassword);
    }

    sqlite3_finalize(stmt);
    return 0;
}

int handle_edit()
{
    int Id;
    char newPassword[50];

    printf("You've chosen to edit a password!\n");
    printf("Please enter the Id of the password you wish to edit:\n");
    if (scanf("%d", &Id) != 1) {
        printf("Invalid input\n");
        return 1;
    }

    printf("Please enter the NEW password:\n");
    if (scanf("%49s", newPassword) != 1) {
        printf("Invalid input\n");
        return 1;
    }

    int rc = edit(Id, newPassword);

    sodium_memzero(newPassword, sizeof newPassword);

    if (rc != 0) {
        printf("Error editing password!\n");
        return 1;
    }

    printf("Password updated successfully.\n");
    printf("\033[H\033[J");
    return 0;
}

int edit(int id, const char *newPassword)
{
    char *encodedPassword = url_encode((char *)newPassword);
    if (!encodedPassword) {
        log_events("program", "error",  "URL encode failed");
        return 1;
    }

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    size_t plaintext_len = strlen(encodedPassword);

    if (plaintext_len > SAVED_PASSWORD_LEN - 1) {
        fprintf(stderr, "New (encoded) password too long (max %d bytes)\n", SAVED_PASSWORD_LEN - 1);
        free(encodedPassword);
        return 1;
    }

    size_t ciphertext_len = crypto_secretbox_MACBYTES + plaintext_len;
    unsigned char ciphertext[ciphertext_len];

    if (encrypt((const unsigned char *)encodedPassword,
                (unsigned long long)plaintext_len,
                MasterKey, nonce, ciphertext) != 0) {
        fprintf(stderr, "Encryption error in edit()\n");
        sodium_memzero(ciphertext, sizeof ciphertext);
        sodium_memzero(nonce, sizeof nonce);
        free(encodedPassword);
        return 1;
    }

    char *err_msg = 0;
    char *sql =
        "UPDATE Passwords "
        "SET Password = ?, Nonce = ?, Ciphertext = ? "
        "WHERE Id == ?;";

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL Error (prepare, edit): %s \n", sqlite3_errmsg(db));
        sqlite3_free(err_msg);
        sqlite3_close(db);
        sodium_memzero(ciphertext, sizeof ciphertext);
        sodium_memzero(nonce, sizeof nonce);
        free(encodedPassword);
        return 1;
    }

    sqlite3_bind_text(stmt, 1, encodedPassword, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, nonce, crypto_secretbox_NONCEBYTES, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 3, ciphertext, (int)ciphertext_len, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, id);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "SQL Error (step, edit): %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        sodium_memzero(ciphertext, sizeof ciphertext);
        sodium_memzero(nonce, sizeof nonce);
        free(encodedPassword);
        return 1;
    }

    sqlite3_finalize(stmt);

    sodium_memzero(ciphertext, sizeof ciphertext);
    sodium_memzero(nonce, sizeof nonce);
    free(encodedPassword);

    return 0;
}


int handle_read() {
    int Id;
    printf("You've chosen to read a password!\n");
    printf("Please enter the Id of the password you wish to read:\n");
    if (scanf("%d", &Id) != 1) {
        printf("Invalid input\n");
        return 1;
    }

    if (read_password(&Id) != 0){
        printf("Error in reading password!\n");
        return 1;
    }
    
    return 0;
}

int list_pass() 
{
    char *err_msg = 0;
    char *sql = "SELECT Id, Site, Account FROM Passwords;";

    int rc = sqlite3_exec(db, sql, callback, 0, &err_msg);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL Error: %s \n", sqlite3_errmsg(db));
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 1;
    }

    return 0;
}

int handle_delete()
{
    int Id;
    char confirm;

    printf("You've chosen to delete a password!\n");
    printf("Please enter the Id of the password you wish to delete:\n");
    if (scanf("%d", &Id) != 1) {
        printf("Invalid input\n");
        return 1;
    }

    printf("Are you sure you want to delete entry with Id %d? (y/N): ", Id);
    if (scanf(" %c", &confirm) != 1) {
        printf("Invalid input\n");
        return 1;
    }

    if (confirm != 'y' && confirm != 'Y') {
        printf("Deletion cancelled.\n");
        return 0;
    }

    int rc = delete_password(Id);
    if (rc != 0) {
        printf("Error deleting password!\n");
        return 1;
    }

    printf("Password deleted successfully.\n");
    return 0;
}

int delete_password(int id)
{
    char *err_msg = 0;
    char *sql = "DELETE FROM Passwords WHERE Id == ?;";

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL Error (prepare, delete): %s\n", sqlite3_errmsg(db));
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 1;
    }

    rc = sqlite3_bind_int(stmt, 1, id);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL Error (bind, delete): %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 1;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "SQL Error (step, delete): %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return 1;
    }

    sqlite3_finalize(stmt);

    int changes = sqlite3_changes(db);
    if (changes == 0) {
        printf("No password with Id %d was found.\n", id);
        return 1;
    }

    return 0;
}


// the code down below is taken from here : https://www.geekhideout.com/urlcode.shtml
char from_hex(char ch) {
  return isdigit((unsigned char)ch) ? ch - '0' : tolower((unsigned char)ch) - 'a' + 10;
}

char to_hex(char code) {
  static char hex[] = "0123456789abcdef";
  return hex[(unsigned char)code & 15];
}

char *url_encode(char *str) {
  char *pstr = str, *buf = malloc(strlen(str) * 3 + 1), *pbuf = buf;
  if (!buf) return NULL;
  while (*pstr) {
    if (isalnum((unsigned char)*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~' || *pstr == ' ') 
      *pbuf++ = *pstr;
    else if (*pstr == ' ') 
      *pbuf++ = '+';
    else 
      *pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
    pstr++;
  }
  *pbuf = '\0';
  return buf;
}

char *url_decode(char *str) {
  char *pstr = str, *buf = malloc(strlen(str) + 1), *pbuf = buf;
  if (!buf) return NULL;
  while (*pstr) {
    if (*pstr == '%') {
      if (pstr[1] && pstr[2]) {
        *pbuf++ = (char)(from_hex(pstr[1]) << 4 | from_hex(pstr[2]));
        pstr += 2;
      }
    } else if (*pstr == '+') { 
      *pbuf++ = ' ';
    } else {
      *pbuf++ = *pstr;
    }
    pstr++;
  }
  *pbuf = '\0';
  return buf;
}
// https://stackoverflow.com/questions/6856635/hide-password-input-on-terminal
ssize_t getpasswd (char **pw, size_t sz, int mask, FILE *fp)
{
    if (!pw || !sz || !fp) return -1;       /* validate input   */
#ifdef MAXPW
    if (sz > MAXPW) sz = MAXPW;
#endif

    if (*pw == NULL) {              /* reallocate if no address */
        void *tmp = realloc (*pw, sz * sizeof **pw);
        if (!tmp)
            return -1;
        memset (tmp, 0, sz);    /* initialize memory to 0   */
        *pw =  (char*) tmp;
    }

    size_t idx = 0;         /* index, number of chars in read   */
    int c = 0;

    struct termios old_kbd_mode;    /* orig keyboard settings   */
    struct termios new_kbd_mode;

    if (tcgetattr (0, &old_kbd_mode)) { /* save orig settings   */
        fprintf (stderr, "%s() error: tcgetattr failed.\n", __func__);
        return -1;
    }   /* copy old to new */
    memcpy (&new_kbd_mode, &old_kbd_mode, sizeof(struct termios));

    new_kbd_mode.c_lflag &= ~(ICANON | ECHO);  /* new kbd flags */
    new_kbd_mode.c_cc[VTIME] = 0;
    new_kbd_mode.c_cc[VMIN] = 1;
    if (tcsetattr (0, TCSANOW, &new_kbd_mode)) {
        fprintf (stderr, "%s() error: tcsetattr failed.\n", __func__);
        return -1;
    }

    /* read chars from fp, mask if valid char specified */
    while (((c = fgetc (fp)) != '\n' && c != EOF && idx < sz - 1) ||
            (idx == sz - 1 && c == 127))
    {
        if (c != 127) {
            if (31 < mask && mask < 127)    /* valid ascii char */
                fputc (mask, stdout);
            (*pw)[idx++] = c;
        }
        else if (idx > 0) {         /* handle backspace (del)   */
            if (31 < mask && mask < 127) {
                fputc (0x8, stdout);
                fputc (' ', stdout);
                fputc (0x8, stdout);
            }
            (*pw)[--idx] = 0;
        }
    }
    (*pw)[idx] = 0; /* null-terminate   */

    /* reset original keyboard  */
    if (tcsetattr (0, TCSANOW, &old_kbd_mode)) {
        fprintf (stderr, "%s() error: tcsetattr failed.\n", __func__);
        return -1;
    }

    if (idx == sz - 1 && c != '\n') /* warn if pw truncated */
        fprintf (stderr, " (%s() warning: truncated at %zu chars.)\n",
                __func__, sz - 1);

    return idx; /* number of chars in passwd    */
}