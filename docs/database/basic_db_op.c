#include <mysql/mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LENGTH 255

void insertDataToDatabase(MYSQL *conn, const char *table, const char *data) {
    char query[512];
    snprintf(query, sizeof(query), "INSERT INTO %s (data) VALUES('%s')", table, data);

    // Execute the SQL query
    if (mysql_query(conn, query)) {
        fprintf(stderr, "Failed to execute query: %s\n", mysql_error(conn));
    }
}

void updateDataInDatabase(MYSQL *conn, const char *table, int id, const char *data) {
    char query[512];
    snprintf(query, sizeof(query), "UPDATE %s SET data = '%s' WHERE id = %d", table, data, id);

    // Execute the SQL query
    if (mysql_query(conn, query)) {
        fprintf(stderr, "Failed to execute query: %s\n", mysql_error(conn));
    }
}

void deleteDataFromDatabase(MYSQL *conn, const char *table, int id) {
    char query[512];
    snprintf(query, sizeof(query), "DELETE FROM %s WHERE id = %d", table, id);

    // Execute the SQL query
    if (mysql_query(conn, query)) {
        fprintf(stderr, "Failed to execute query: %s\n", mysql_error(conn));
    }
}

void retrieveDataFromDatabase(MYSQL *conn, const char *table) {
    MYSQL_RES *res;
    MYSQL_ROW row;

    char query[512];
    snprintf(query, sizeof(query), "SELECT * FROM %s", table);

    // Execute the SQL query
    if (mysql_query(conn, query)) {
        fprintf(stderr, "Failed to execute query: %s\n", mysql_error(conn));
        return;
    }

    // Get the result set
    res = mysql_use_result(conn);

    // Retrieve and print the data
    while ((row = mysql_fetch_row(res))) {
        printf("ID: %s, Data: %s\n", row[0], row[1]);
    }

    // Free the result set
    mysql_free_result(res);
}

int main() {
    MYSQL *conn;
    const char *server = "your_mysql_server";
    const char *user = "your_mysql_user";
    const char *password = "your_mysql_password";
    const char *database = "your_mysql_database";
    const char *table = "your_table_name";

    conn = mysql_init(NULL);

    // Connect to the database
    if (!mysql_real_connect(conn, server, user, password, database, 0, NULL, 0)) {
        fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(conn));
        mysql_close(conn);
        return 1;
    }

    // Insert data
    const char *data1 = "Data 1";
    const char *data2 = "Data 2";
    insertDataToDatabase(conn, table, data1);
    insertDataToDatabase(conn, table, data2);

    // Retrieve all data
    retrieveDataFromDatabase(conn, table);

    // Update data
    const char *updatedData = "Updated Data";
    updateDataInDatabase(conn, table, 1, updatedData);

    // Retrieve all data after update
    retrieveDataFromDatabase(conn, table);

    // Delete data
    deleteDataFromDatabase(conn, table, 2);

    // Retrieve all data after delete
    retrieveDataFromDatabase(conn, table);

    // Close the database connection
    mysql_close(conn);

    return 0;
}
