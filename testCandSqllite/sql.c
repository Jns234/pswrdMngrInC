#include <stdio.h>
#include <sqlite3.h>
#include <string.h>


int callback(void *NotUsed, int argc, char **argv, char **azColName)  {
    return 0;
}

int insert_data(sqlite3 *db) {
    char *err_msg = 0;
    char *sql = "INSERT INTO Friends(Name) VALUES('Tom');";

    int rc = sqlite3_exec(db, sql, callback, 0, &err_msg);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL Error: %s \n", sqlite3_errmsg(db));

        sqlite3_free(err_msg);
        sqlite3_close(db);
        
        return 1;
    }

    return 0;
}


int main() {
    sqlite3 *db;
    char *err_msg=0;

    int rc = sqlite3_open("test.db", &db);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot connect to database: %s \n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        return 1;
    }

    char *sql = "CREATE TABLE IF NOT EXISTS Friends(Id INTEGER PRIMARY KEY, Name TEST);";

    rc = sqlite3_exec(db,sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL Error: %s \n", sqlite3_errmsg(db));

        sqlite3_free(err_msg);
        sqlite3_close(db);
        
        return 1;
    }
    
    insert_data(db);

    sqlite3_close(db);


    return 0;
}
