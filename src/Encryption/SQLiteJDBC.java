package Encryption;

import java.sql.Connection;
import java.sql.DriverManager;

public class SQLiteJDBC {
    public static void CreateConnection()
    {
        Connection connection = null;
        try {
            Class.forName("org.sqlite.JDBC");
            connection = DriverManager.getConnection("jdbc:sqlite:user_info.db");
        } catch ( Exception e ) {
            System.err.println( e.getClass().getName() + ": " + e.getMessage() );
            System.exit(0);
        }
        System.out.println("Opened database successfully");
    }

    public static void CloseConnection() {

    }
}
