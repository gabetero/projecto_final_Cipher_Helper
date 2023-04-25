#include <fstream>
#include <string>
#include <iomanip>
#include <sstream>
#include <cryptopp/cryptlib.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <vector> // vectores
#include <string> // manipulacion de string
#include <cstdio>//para esperar a que el usuario presses a key to continue
#include <cctype>

using namespace std;
using namespace CryptoPP;

const string PASSWORD_FILE = "password.txt";
const string USERNAME_FILE = "username.txt";


// Esta funcion covierte el password a hash
string HashPassword(const string& password) {
    SHA256 hash;
    string digest;
    StringSource(password, true,
        new HashFilter(hash, new HexEncoder(new StringSink(digest))));
    return digest;
}

// Esta funcion guarda el hash al file
void SavePassword(const string& password) {

    string hashMake = HashPassword(password);

    ofstream fout(PASSWORD_FILE, fstream::app);

    if (fout) {

        fout << hashMake<<endl;
        cout << "Password guardado!" << endl;
    }
    else {
        cerr << "Error: No se pudo abrir el archivo para escribi" << endl;
    }
}

// La funcion lee el hash del password del archivo.
string ReadPassword() {

    string password;

    ifstream fin(PASSWORD_FILE);

    if (fin) {
        getline(fin, password);
    }
    else {
        cerr << "Error: no se pudo leer el archivo" << endl;
    }
    return password;
}

// Function para guardar el username al password.
void SaveUsername(const string& username) {

    ofstream fout(USERNAME_FILE, fstream::app);

    if (fout) {

        fout << username<<endl;
        cout << "Username guardado!" << endl;
    }
    else {
        cerr << "Error: No se pudo abrir el archivo para escribir" << endl;
    }
}

// Funcion para leer el username del archivo
string ReadUsername() {

    string username;

    ifstream fin(USERNAME_FILE);

    if (fin) {

        getline(fin, username);
    }
    else {
        cerr << "Error: No se pudo leer el archivo" << endl;
    }
    return username;
}

bool VerifyPassword(const string& username, const string& password) {

    string hashed_password = ReadPassword();
    

    string new_hash = HashPassword(password);
  

    if (new_hash == hashed_password) {

        return true;
    }

    else if (new_hash != hashed_password) {

        return false;
    }

}

bool usernameExists(const string& username) {

    string line;
    ifstream fin(USERNAME_FILE);

    if (fin) {

        while (getline(fin, line)) {

            if (line == username) {

                return true;
            }
        }

        fin.close();
    }

    return false;
}


char shiftChar(char c, int key) {

    if (isalpha(c)) {//se verifica si es una letra para proceder al cifrado de la misma

        if (isupper(c)) {//se utiliza isupper para verificar si la palabra es mayuscula

            c = ((c - 'A') + key) % 26 + 'A';
        }
        else if (islower(c)) {//se utiliza islower para verificar si la palabra es minuscula

            c = ((c - 'a') + key) % 26 + 'a';
        }

    }

    return c;
}

//funcion que hace el shift del ceasar cipher (adrian)

char shiftCeasar(char d) {

    if (isalpha(d)) {

        if (isupper(d)) {

            d = ((d - 'A') + 3) % 26 + 'A';
        }
        else if (islower(d)) {

            d = ((d - 'a') + 3) % 26 + 'a';
        }
    }

    return d;
}

string encrypt(string plaintext, string keyVig) {

    string ciphertext = "";

    int keylen = keyVig.length();
    int j = 0;  // index into key

    for (int i = 0; i < plaintext.length(); i++) {

        char c = plaintext[i];

        if (isalpha(c)) {

            c = toupper(c);  // convert to uppercase for simplicity
            int shift = keyVig[j] - 'A';  // convert key letter to shift amount
            c = ((c - 'A' + shift) % 26) + 'A';  // apply shift and convert back to letter
            j = (j + 1) % keylen;  // move to next key letter
        }
        ciphertext += c;
    }
    return ciphertext;
}

string decrypt(string cipherCode, string userinputKey) {

    string plaintext = "";

    int keylen = userinputKey.length();
    int j = 0;  // index into key

    for (int i = 0; i < cipherCode.length(); i++) {

        char c = cipherCode[i];
        if (isalpha(c)) {
            c = toupper(c);  // convert to uppercase for simplicity
            int shift = userinputKey[j] - 'A';  // convert key letter to shift amount
            c = (((c - 'A' - shift) % 26) + 26) % 26 + 'A';  // apply shift and convert back to letter
            j = (j + 1) % keylen;  // move to next key letter
        }
        plaintext += c;
    }
    return plaintext;
}






void loginMenu() {

        system("cls");
        cout << "==========================" << endl;
        cout << "         LOGIN MENU        " << endl;
        cout << "==========================" << endl;
        cout << "Select an option:" << endl;
        cout << "(1) Create Account" << endl;
        cout << "(2) Log In" << endl;
        cout << "(3) Exit" << endl;
        cout << "==========================" << endl;
   

}

void principalMenu() {

    system("cls");
    
    cout << "==========================" << endl;
    cout << "    MENU CYPHER HELP        " << endl;
    cout << "==========================" << endl;
    cout << "Select an option:" << endl;
    cout << "(1) Cifrar" << endl;
    cout << "(2) Desifrar" << endl;
    cout << "(3) Log out" << endl;
    cout << "==========================" << endl;


}

void cipherMenu() {

    system("cls");

    cout << "==========================" << endl;
    cout << "    MENU CIPHER HELP        " << endl;
    cout << "==========================" << endl;
    cout << "Select an option:" << endl;
    cout << "(1) Shift Cipher" << endl;
    cout << "(2) Vigenere Cipher" << endl;
    cout << "(3) Ceasar Cipher  " << endl;
    cout << "(4) Rail Fence Cipher   " << endl;
    cout << "==========================" << endl;


}

void insertText() {
    
    system("cls");
    cout << "==========================" << endl;
    cout << " INSERTE PALABRA A CIFRAR    " << endl;
    cout << "==========================" << endl;
    cout << "-->";
    

}

void keyinsertText() {

    system("cls");
    cout << "==========================" << endl;
    cout << "      INSERTE LLAVE   " << endl;
    cout << "==========================" << endl;
    cout << "-->";


}

void userText() {

    system("cls");
    cout << "==========================" << endl;
    cout << "      INSERTE USERNAME   " << endl;
    cout << "==========================" << endl;
    cout << "-->";


}

void passText() {

    system("cls");
    cout << "==========================" << endl;
    cout << "     INSERTE PASSWORD   " << endl;
    cout << "==========================" << endl;
    cout << "-->";


}

int main() {


    int choice;
    do {

        loginMenu();
        cin >> choice;

        switch (choice) {

        case 1: {

            string username, password;
            userText();
            cin >> username;

            if (usernameExists(username)) {

                cout << "El username ya existe" << endl;

               
            }
            else {

                passText();

                cin >> password;

                SaveUsername(username);


                SavePassword(password);
            }

           

           
        }
        case 2: {

            string username, password;

            userText();
            cin >> username;



            if (!usernameExists(username)) {

                cout << "El username no existe" << endl;



            }
            else {
                passText();
                cin >> password;

                bool result = VerifyPassword(username, password);

                if (result == false) {

                    cout << "Password incorrecto" << endl;

                    system("cls");


                }
                else if (result == true) {

                    int choicemenuPrincipal = 0;

                    do {
                        principalMenu();

                        cin >> choicemenuPrincipal;

                        system("cls");
                        switch (choicemenuPrincipal) {

                        case 1:
                        {
                            cipherMenu();

                            int cipherChoice;
                            cin >> cipherChoice;
                            cin.ignore(); //se utiliza para limpiar el input buffer para que se pueda utilizar getline
                            system("cls");



                            switch (cipherChoice) {

                               case 1: {

                                 insertText();

                                 string input;
                                 getline(cin, input); // read a line of input

                                 int key;

                                 system("cls");

                                 keyinsertText();

                                 cin >> key;


                                 vector<char> cipherText;
                                 vector<char> bruteForce;

                                // loop over the characters in the input string

                                  for (char c : input) {


                                    // shift the character by the random amount
                                    char shifted = shiftChar(c, key);

                                    // add the shifted character to the output vector
                                    cipherText.push_back(shifted);


                                  }

                                cout << "Su palabra cifrada es: ";
                                // print the shifted message
                                  for (char c : cipherText) {

                                    cout << c;
                                  }

                                 cout << endl << "Apunte su cifrado" << endl;
                                 cout << "Presiona cualquier letra para continuar a nuestro menu principal" << endl;

                                system("pause");//funcion para esperar key input para continuar

                                system("cls");
                                //menu log in


                                break;

                               }

                            case 2: {

                                string plaintext, keyVig;

                                insertText();
                                cin >> plaintext;

                                keyinsertText();
                                cin >> keyVig;

                                string ciphertext = encrypt(plaintext, keyVig);
                                cout << "Plaintext: " << plaintext << endl;
                                cout << "Key: " << keyVig << endl;
                                cout << "Ciphertext: " << ciphertext << endl;

                                system("pause");//funcion para esperar key input para continuar

                                system("cls");

                                break;

                            }

                            case 3: {

                                 
                                insertText();

                                string input;
                                getline(cin, input); // read a line of input

                                int key;

   
                                keyinsertText();


                                cin >> key;


                                vector<char> cipherText;
                                vector<char> bruteForce;

                                vector<char> ceasarText;

                                //  implement ceasar cipher
                                for (char d : input) {
                                    //shift character to 3
                                    char shifting = shiftCeasar(d);

                                    //add shifted character to output vector
                                    ceasarText.push_back(shifting);

                                }
                                cout << "                    + ------------------------------------------------------------- + " << endl;
                                cout << "                    |  Dale click a cualquier tecla para proceder al menu principal |" << endl;
                                cout << "                    |                   Recuerde guardar su cifrado                 | " << endl;
                                cout << "                    + ------------------------------------------------------------- +" << endl;
                                cout << "\n\n                               Su palabra cifrada es: ";
                                for (char d : ceasarText) {

                                    cout << d;
                                }


                                cout << endl;

                                system("pause");//funcion para esperar key input para continuar

                                system("cls");

                                break;
                            }
                            case 4: {
                                string inputRail;
                                int keyRail;
                                cout << "Enter the message you want to encrypt: ";
                                getline(cin, inputRail);

                                keyinsertText();
                                cin >> keyRail;

                                if (keyRail <= 1) {
                                    cout << "Error: Invalid key value." << endl;
                                    return 0;
                                }

                                int len = inputRail.length();

                                vector<vector<char>> rail(keyRail, vector<char>(len, '.'));
                                bool dir_down = false;
                                int row = 0, col = 0;

                                for (int i = 0; i < len; i++) {
                                    if (row == 0 || row == keyRail - 1) {
                                        dir_down = !dir_down;
                                    }
                                    rail[row][col] = inputRail[i];
                                    col++;
                                    if (dir_down) {
                                        row++;
                                    }
                                    else {
                                        row--;
                                    }
                                }

                                string encrypted;
                                row = 0, col = 0;

                                for (int i = 0; i < len; i++) {
                                    if (row == 0 || row == keyRail - 1) {
                                        dir_down = !dir_down;
                                    }
                                    encrypted += rail[row][col];
                                    col++;
                                    if (dir_down) {
                                        row++;
                                    }
                                    else {
                                        row--;
                                    }
                                }

                                cout << "Encrypted message: " << encrypted << endl;
                                system("pause");
                            }
                            }

                            break;

                        }
                        case 2: {

                            cin.ignore();

                            insertText();

                            string cipherCode;

                            getline(cin, cipherCode);

                          
                            

                            cout << "Seleccione el tipo de llave" << endl;
                            cout << "(1) numerico" << endl;
                            cout << "(2) caracter" << endl;

                            int keyType;
                            cin >> keyType;

                            keyinsertText();

                            int userinputKey;

                            cin >> userinputKey;

                            if (keyType == 1) {

                                int contador = 0;

                                while (contador <= 1) {//se utiliza loop bool para validacion de user input(y/n)


                                    cout << endl << "Sabe usted la llave de su cifrado? (Y/N)\n--->";

                                    char userInput;
                                    cin >> userInput;

                                    if (toupper(userInput) == 'Y') {

                                        contador = 2;//salir del loop de validacion de input

                                        for (char c : cipherCode) {

                                            if (isalpha(c)) {//se verifica si es una letra para proceder al cifrado de la misma

                                                if (isupper(c)) {//se utiliza isupper para verificar si la palabra es mayuscula

                                                    c = ((c - 'A') + userinputKey) % 26 + 'A';
                                                }
                                                else if (islower(c)) {//se utiliza islower para verificar si la palabra es minuscula

                                                    c = ((c - 'a') + userinputKey) % 26 + 'a';
                                                }

                                            }

                                            cout << c;



                                        }
                                    }
                                    else if (toupper(userInput) == 'N') {

                                        contador = 2;

                                        system("CLS");
                                        cout << "+ -------------------------------------------------------------------------------------------------------------- + " << endl;
                                        cout << "|     No te preocupes, podemos realizar un ataque de fuerza bruta que nos de todas las convinaciones posibles    |" << endl;
                                        cout << "|                           Dale click a cualquier tecla para proceder con el ataque                             |" << endl;
                                        cout << "+ -------------------------------------------------------------------------------------------------------------- +" << endl;

                                        system("pause");
                                        system("cls");

                                        for (int x = 1; x <= 25; x++) {

                                            cout << "Shift #" << x << ":";

                                            for (char c : cipherCode) {

                                                if (isalpha(c)) {//se verifica si es una letra para proceder al cifrado de la misma

                                                    if (isupper(c)) {//se utiliza isupper para verificar si la palabra es mayuscula

                                                        c = ((c - 'A') + x) % 26 + 'A';
                                                    }
                                                    else if (islower(c)) {//se utiliza islower para verificar si la palabra es minuscula

                                                        c = ((c - 'a') + x) % 26 + 'a';
                                                    }

                                                }



                                                cout << c;

                                            }
                                            cout << endl;
                                        }
                                    }
                                    else {
                                        cout << "Error, favor de intentar de nuevo";

                                    }
                                }
                            }
                            else if (keyType == 2 && isalpha(userinputKey)) {

                                //decrypt(cipherCode, userinputKey);

                            }


                            system("pause");
                            system("cls");

                            break;
                        }
                        }

                    } while (choicemenuPrincipal < 3);


                }

            }

            }


        

        }


    }while (choice != 3);
}