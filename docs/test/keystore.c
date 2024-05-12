#include <stdio.h>
#include <mysql.h>

// Define your KeyPkg structure here

int main() {
    MYSQL *conn;
    MYSQL_STMT *stmt;
    MYSQL_BIND bind[15]; // 有15个列

    // Initialize MySQL connection handler
    conn = mysql_init(NULL);

    // Connect to MySQL database
    if (!mysql_real_connect(conn, "hostname", "username", "password", "database_name", 0, NULL, 0)) {
        fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(conn));
        mysql_close(conn);
        return 1;
    }

    // Prepare INSERT statement
    stmt = mysql_stmt_init(conn);
    if (!stmt) {
        fprintf(stderr, "Failed to initialize statement: Error: %s\n", mysql_error(conn));
        mysql_close(conn);
        return 1;
    }

    // Define INSERT statement
    const char *insert_sql = "INSERT INTO KeyPkg VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    if (mysql_stmt_prepare(stmt, insert_sql, strlen(insert_sql))) {
        fprintf(stderr, "Failed to prepare statement: Error: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        mysql_close(conn);
        return 1;
    }

    // Bind parameters
    // You need to bind parameters for each '?' in the SQL statement
    // Example:
    // mysql_stmt_bind_param(stmt, &bind[0]); // Bind first parameter

    // Execute the INSERT statement
    if (mysql_stmt_execute(stmt)) {
        fprintf(stderr, "Failed to execute statement: Error: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        mysql_close(conn);
        return 1;
    }

    // Close statement
    mysql_stmt_close(stmt);

    // Close MySQL connection
    mysql_close(conn);

    return 0;
}
