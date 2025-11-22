#include <stdio.h>
#include <sqlite3.h>
#include <string.h>
#include <stdint.h>
#include <sodium.h>
#include <unistd.h>

#define SQL_FILE "test.db"
#define SQLITE_HAS_CODEC 1

// Declaring the pointerfor the sqlite db
sqlite3 *db;
sqlite3_stmt *stmt = NULL;


char MasterKey[20];
int i;
char *passwordDb = "demo";


// Need to declare functions
int init_db();
int add_pass(char* Account, char* Site, char* Password);
int list_pass();
int handle_pass_insert();
int handle_read();
int read_password(int *Id);
int AskForPassword();
int checkInitiaMaster();
void initMasterPass();
int getMasterhash(char *out, size_t out_size);
int check_db();

int callback(void *NotUsed, int argc, char **argv, char **azColName)  {
    for (int i = 0; i < argc; i++){
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL" );
    }
    printf("\n");

    return 0;
}

typedef struct StoredPassword {
  int Id;
  uint8_t *Site;
  uint8_t *Account;
  uint8_t *Password;

} StoredPassword;


int main()
{   
    typedef enum commands {
        save = 0,
        list,
        read,
        edit
    }CMND;

    if (sodium_init() < 0) {
        /* panic! the library couldn't be initialized; it is not safe to use */
        return 1;
    }

    init_db();

    MasterKeyStart:
    if ( AskForPassword() != 0) {
        printf("Couldn't log in!\n");
        return 1;
    }
    
    Start:

    int command;

    printf("This is the CLI Password Manager prototype!\n");

    printf("Waiting for a command\n");

    scanf("%d", &command);

    printf("Your command: %d\n", command);

    CMND cmdn = command;

    switch (cmdn)
    {
    case save:
        printf("You chose to save\n");
        handle_pass_insert();
        goto Start;
    case list:
        printf("You chose to list\n");
        list_pass();
        goto Start;
    case read:
        handle_read();
        goto Start;
    case edit:
        printf("You chose to edit\n");
        goto Start;    

    default:
        break;
        sqlite3_close(db);
    }
    sqlite3_close(db);
    return 0;
}

int handle_edit()
{

}


int edit()
{

}

int handle_read() {
    int Id;
    printf("You've chosen to read a password!\n");
    printf("Please enter the Id of the password you wish to read:\n");
    scanf("%d", &Id);

    read_password(&Id);
    
    return 0;

}


int read_password(int* Id)
{

    char *err_msg = 0;
    char *sql = "SELECT Id, Site, Account, Password FROM Passwords WHERE Id == ?;";
    
    int rc = sqlite3_prepare_v2(db, sql, strlen(sql)+1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL Error: %s \n", sqlite3_errmsg(db));
        sqlite3_free(err_msg);
        sqlite3_close(db);

        return 1;
    }

    sqlite3_bind_int(stmt, 1, *Id);
    StoredPassword spassword;

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        spassword.Id = sqlite3_column_int(stmt, 0);
        spassword.Site = (uint8_t *)sqlite3_column_text(stmt, 1);
        spassword.Account = (uint8_t *)sqlite3_column_text(stmt, 2);
        spassword.Password = (uint8_t *)sqlite3_column_text(stmt, 3);
        printf("Id: %d, Site: %s, Account: %s, Password: %s\n", spassword.Id, spassword.Site, spassword.Account, spassword.Password);
    }

    sqlite3_finalize(stmt);
    return rc;
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


int handle_pass_insert() {
    char Account[30];
    char Site[40];
    char Password[30];

    printf("You've chosen to add a password!\n");

    printf("Please enter the email/account you wish to add:\n");
    scanf("%s", Account);

    printf("Please enter the site you wish to add:\n");
    scanf("%s", Site);

    printf("Please enter the password you wish to add:\n");
    scanf("%s", Password);

    printf("Here's waht you will add: %s, %s, %s \n", Account, Site, Password);
    
    add_pass(Account, Site, Password);

    return 0;
}

int add_pass(char *Account, char *Site, char *Password) 
{
    char *err_msg = 0;
    char *sql = "INSERT INTO Passwords(Account, Site, Password) VALUES(?, ?, ?);";

    //int rc = sqlite3_exec(db, sql, callback, 0, &err_msg);
    int rc = sqlite3_prepare_v2(db, sql, strlen(sql)+1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL Error: %s \n", sqlite3_errmsg(db));

        sqlite3_free(err_msg);
        sqlite3_close(db);
        
        return 1;
    }

    sqlite3_bind_text(stmt, 1, Account, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, Site, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, Password, -1, SQLITE_STATIC);
 
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return rc;
}
int check_db()
{
    if (access(SQL_FILE, F_OK) == 0) {
        return 0;
    } else {
        return 1;
    }
}

int init_db()
{

    if (check_db() != 0) {
        printf("No database file present");
    }

    char *err_msg  = 0;
    int response_code = sqlite3_open(SQL_FILE, &db);

    if (response_code != SQLITE_OK) {
        fprintf(stderr, "Cannot connect to database: %s \n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        return 1;
    }

    response_code = sqlite3_key(db, passwordDb, strlen(passwordDb));
    
    if(response_code != SQLITE_OK){
    printf("failed to key database\n");
    }

    char *sql = "CREATE TABLE IF NOT EXISTS Passwords(Id INTEGER PRIMARY KEY, Account TEXT, Site TEXT, Password TEXT);";
    char *sqlHash ="CREATE TABLE IF NOT EXISTS Hash (Key TEXT PRIMARY KEY, Value TEXT);";

    response_code = sqlite3_exec(db,sql, 0, 0, &err_msg);
    if (response_code != SQLITE_OK) {
        fprintf(stderr, "SQL Error: %s \n", sqlite3_errmsg(db));

        sqlite3_free(err_msg);
        sqlite3_close(db);
        
        return 1;
    }
    response_code = sqlite3_exec(db,sqlHash, 0, 0, &err_msg);
    if (response_code != SQLITE_OK) {
        fprintf(stderr, "SQL Error: %s \n", sqlite3_errmsg(db));

        sqlite3_free(err_msg);
        sqlite3_close(db);
        
        return 1;
    }

    return 0;
}

int checkInitiaMaster()
{
    char *err_msg = 0;
    char *sql = "SELECT count(*) from Hash;";

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL Error: %s \n", sqlite3_errmsg(db));

        sqlite3_free(err_msg);
        sqlite3_close(db);
        
        return 1;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        fprintf(stderr, "SQL Error in getting hash: %s \n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        
        return 1;
    }

    int count = sqlite3_column_int(stmt, 0);
    printf("Count of row %d", count);

    return count;
}

void initMasterPass() {
    char MasterPassword[20];
    char hashed_password[crypto_pwhash_STRBYTES];

	printf("\n");
	printf("Create your MASTER PASSWORD: \n");
    scanf("%20s", MasterPassword);

    if (crypto_pwhash_str(hashed_password, MasterPassword, strlen(MasterPassword), crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
    /* out of memory */
    }
    
   //printf("The hash: %s", hashed_password);
    
    char *err_msg = 0;
    char *sql = "INSERT INTO Hash(Key, Value) VALUES(?, ?);";

    //int rc = sqlite3_exec(db, sql, callback, 0, &err_msg);
    int rc = sqlite3_prepare_v2(db, sql, strlen(sql)+1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL Error: %s \n", sqlite3_errmsg(db));

        sqlite3_free(err_msg);
        sqlite3_close(db);
        
        return;
    }

    sqlite3_bind_text(stmt, 1, "Master", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hashed_password, -1, SQLITE_STATIC);
 
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

}

int getMasterhash(char *out, size_t out_size)
{
    // First proper function where I try to manage memory in an acceptable way
    char *err_msg = 0;
    char *sql = "Select Value from Hash where Key == \"Master\";";

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL praparation Error: %s \n", sqlite3_errmsg(db));
        return 1;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        fprintf(stderr, "SQL Error in getting hash: %s \n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        
        return 1;
    }

    const char *hash = sqlite3_column_text(stmt, 0);
    int len = sqlite3_column_bytes(stmt, 0);
    
    // Remember to keep checking buffer sizes, maybe a helper function would be a good option?
    if ((size_t)len >= out_size) {
        fprintf(stderr, "Buffer too small\n");
        sqlite3_finalize(stmt);
        return 1;
    }

    // First proper use of memcpy, should keep on using it as it's pure spaghetti atm
    memcpy(out, hash, len);
    out[len] = '\0'; // not sure if null termination is always needed atm

    sqlite3_finalize(stmt);

    return 0;
}

int AskForPassword() {
    char hashed_password[crypto_pwhash_STRBYTES];
    char MasterPassword[20];
	
    int rowCount = checkInitiaMaster();

    if (rowCount == 0) {
        initMasterPass();
    } 

    if (getMasterhash(hashed_password, sizeof hashed_password) != 0) {
        printf("Error, could not get password hash!\n");
        return 1;
    }

	for (i = 0; i < 3; i++) {

		printf("\n");
		printf("What is the MASTER PASSWORD: \n");
		scanf("%20s", MasterPassword);
		printf("\n");

					
    if (crypto_pwhash_str_verify(hashed_password, MasterPassword, strlen(MasterPassword)) == 0) {	
			printf(">> CORRECT PASSWORD. ACCESS CONFIRMED <<\n");
			printf("\n");
			return 0;
		
		}
		else {
			
			if (i == 2) {
				
				printf(">> WRONG PASSWORD. ACCESS DENIED. PROGRAM ENDED <<\n");
				printf("\n");
				return 1; 
			}
				
			printf("Wrong password. Try again...");
			
		}	
	
	}
	
}