#include <stdio.h>
#include <stdlib.h> // For malloc() and free()
#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <ctype.h>

// Asking the user to input their own password and message
// Using SHA-256 to derive a key from the user's password.
// Use the derived key to compute HMAC-SHA-256 of the message.
// Show the SHA-256 hash of the password and the HMAC-SHA-256 of the message in hexadecimal format

#define SALT_SIZE 32 // 32 bytes for the salt, extra security

// Make function to compute the SHA-256 HASH to derive a key from users password
void compute_SHA256(const char *input, size_t input_len, unsigned char output[SHA256_DIGEST_LENGTH]){
    SHA256((unsigned char*)input, input_len, output);
}


// Make function to compute the HMAC_SHA-256 secret key to verify 
// integrity and authenticity of the message being sent through
void compute_HMAC_SHA256(const unsigned char *key, size_t key_len, const char *message, unsigned char output[SHA256_DIGEST_LENGTH]){
    unsigned int len = SHA256_DIGEST_LENGTH;
    HMAC(EVP_sha256(), key, key_len, (unsigned char*)message, strlen(message), output, &len);
}

// Function to print hash in hexadecimal format
void print_hex(const char *label, unsigned char hash[], size_t length){
    printf("%s", label);
    for(size_t i =0; i < length; i++){
        printf("%02x", hash[i]);
    }
    printf("\n");
}


//Function for geting the users input for password and message

char *get_user_input(const char *prompt){

    // Need to use free() to free the memory allocated 
    // Use getline() to get the user input

    char *line = NULL; // Pointer to the a char, to store the input
    size_t size = 0; // Size of the input buffer

    printf("%s", prompt); // Give user a prompt
    ssize_t len = getline(&line, &size, stdin); // Using getline() to read the entire input


    // Error check if getline() fails
    if( len == -1){
        free(line); // Free the memory allocated
        printf("Error: Reading the user input \n.");
        return NULL;
    }

    // Remove newline character
    line[strcspn(line, "\n")] = 0;
    return line; // Caller must free() the memory allocated

}


// Generate Random Salt(16-32 bytes) and concatenate salt+password before hashing
// Store Salt+Hash together for verification
void generate_salt(unsigned char *salt, size_t length){
    if(RAND_bytes(salt, length) != 1){
        printf("Error: Generating random salt.\n");
        return;
    }
}


// Returns an int because it assigns a numerical strength rating to the password
// Rating will give user feedback on how strong password is
// Will enforce password rules(rejecting weak passwords)

int check_password_strength(const char *password){
    int length = strlen(password);
    int has_upper = 0, has_lower = 0, has_digit = 0, has_special = 0;

    for(int i = 0; i < length; i++){
        if(isupper(password[i])) has_upper = 1;
        if(islower(password[i])) has_lower = 1;
        if(isdigit(password[i])) has_digit = 1;
        if(ispunct(password[i])) has_special = 1;
    }
    
    // Debugging: Print which categories were found
    printf("\n[DEBUG] Password Analysis: UPPER(%d) LOWER(%d) DIGIT(%d) SPECIAL(%d)\n", 
            has_upper, has_lower, has_digit, has_special);

    // Compute score
    int score = has_upper + has_lower + has_digit + has_special;

    if(length < 8){
        printf("❌ Weak Password (Too short, must be at least 8 characters)\n");
        return 0;
    }
    if(score == 1){
        printf("❌ Weak Password (Must include more complexity)\n");
        return 1;
    }
    if(score == 2){
        printf("⚠️  Medium Password (Consider adding numbers or special characters)\n");
        return 2;
    }
    if(score == 3){
        printf("✅ Strong Password\n");
        return 3;
    }
    if(score == 4){
        printf("🔒 Very Strong Password\n");
        return 4;
    }

    return 0; // Default case, should never hit this
}


int main(){

    // Get user input for password
    char *password = get_user_input("Enter your password: \n");
    if(!password) return 1;
    
    if(strlen(password) == 0){
        printf("%s\n", "Error: No password entered.");
        return 1;
    }


    // Check password strength
    int strength = check_password_strength(password);
    // Make a loop for user to retry password if it is weak
    while(strength <= 1){
        free(password);
        password = get_user_input("Enter your password: \n");
        if(!password) return 1;
        password[strcspn(password, "\n")] = 0;  // Remove newline
        strength = check_password_strength(password);
    }

    // Get user input for message
    char *message = get_user_input("Enter your message: \n");
    if(!message){
        printf("%s\n", "Error: No message entered.");
    }

    // Generate random salt data
    unsigned char salt[SALT_SIZE];
    generate_salt(salt, SALT_SIZE);

    // Combine Salt+Password
    size_t password_len = strlen(password);
    size_t salted_password_len = password_len + SALT_SIZE;
    unsigned char *salted_password = malloc(salted_password_len);

    // Error check if malloc() fails
    if(!salted_password){
        printf("Error: Memory allocation failed.\n");
        free(password);
        free(message);
        return 1;
    }
    memcpy(salted_password, salt, SALT_SIZE); // Copy the salt to the salted_password
    memcpy(salted_password + SALT_SIZE, password, password_len); // Copy the password to the salted_password

    // Compute SHA-256 hash of (Salt + Password)
    unsigned char password_hash[SHA256_DIGEST_LENGTH];
    compute_SHA256((char *)salted_password, salted_password_len, password_hash);

    // Computer HMAC-SHA-256 of the message using hashed password as a key
    unsigned char HMAC_hash[SHA256_DIGEST_LENGTH];
    compute_HMAC_SHA256(password_hash, SHA256_DIGEST_LENGTH, message, HMAC_hash);

    // Print Results of everything
    print_hex("Generated Salt: ", salt, SALT_SIZE);
    print_hex("SHA-256 Hash of Password: ", password_hash, SHA256_DIGEST_LENGTH);
    print_hex("HMAC-SHA-256 of Message: ", HMAC_hash, SHA256_DIGEST_LENGTH);
    // Free allocated dynamic memory
    free(password);
    free(message);
    free(salted_password);

    return 0;
}