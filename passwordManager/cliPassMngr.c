#include <stdio.h>
#include <sqlite3.h>
#include <string.h>

#define SQL_FILE "test.db"

// Declaring the pointerfor the sqlite db
sqlite3 *db;
sqlite3_stmt *stmt = NULL;



// Need to declare functions
int init_db();
int add_pass(char* Account, char* Site, char* Password);
int list_pass();
int handle_pass_insert();
int handle_read();

int callback(void *NotUsed, int argc, char **argv, char **azColName)  {
    for (int i = 0; i < argc; i++){
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL" );
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
        edit
    }CMND;

    Start:
    init_db();
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
        printf("You chose to read\n");
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

int handle_read() {

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


int init_db()
{
    char *err_msg  = 0;
    int response_code = sqlite3_open(SQL_FILE, &db);

    if (response_code != SQLITE_OK) {
        fprintf(stderr, "Cannot connect to database: %s \n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        return 1;
    }

    char *sql = "CREATE TABLE IF NOT EXISTS Passwords(Id INTEGER PRIMARY KEY, Account TEXT, Site TEXT, Password TEXT);";


    response_code = sqlite3_exec(db,sql, 0, 0, &err_msg);
    if (response_code != SQLITE_OK) {
        fprintf(stderr, "SQL Error: %s \n", sqlite3_errmsg(db));

        sqlite3_free(err_msg);
        sqlite3_close(db);
        
        return 1;
    }

    return 0;
}


