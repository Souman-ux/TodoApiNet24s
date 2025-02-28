using System;
using System.Collections.Generic;

public static class UserStore
{
    // A dictionary to store users with their username as the key and the User object as the value
    public static Dictionary<string, User> Users = new Dictionary<string, User>
    {
        { "admin", new User { Username = "admin", PasswordHash = "password" } },
        { "user", new User { Username = "user", PasswordHash = "userpassword" } }
    };

    // Method to add a new user with their username and password hash
    public static void AddUser(string username, string passwordHash)
    {
        // Store the user in the dictionary
        Users[username] = new User
        {
            Username = username,
            PasswordHash = passwordHash
        };
    }

    // Method to retrieve a user by username
    public static User GetUser(string username)
    {
        // Try to get the user by username
        Users.TryGetValue(username, out var user);
        return user;
    }
}
