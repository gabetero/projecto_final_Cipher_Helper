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
    SHA256 hash; // Se usa la instancia SHA 256 para convertir el password a un valor en hash.
    string digest; // variable para guardar el hash en hexadecimal
    StringSource(password, true, // string source toma el password y lo establece como la fuente de datos para el hash. true indica que input ser enviado al pipeline de los filtros todo de una vez.
        new HashFilter(hash, new HexEncoder(new StringSink(digest))));
    return digest; // HashFilter calcula el valor de hash del input, lo manda a HexEnconder lo convierte de binario a hexadecimal para que el manejo sea mas eficiente. StringSink se usa para guardar el hash resultante en el string digest y luego la funcion devuelve el hash que representa al password.
}

// Esta funcion guarda el hash al file
void SavePassword(const string& password) {

    string hashMake = HashPassword(password);

    ofstream fout(PASSWORD_FILE, fstream::app);

    if (fout) {

        fout << hashMake << endl;
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

        fout << username << endl;
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
        else if (c == ' ') {
            ciphertext += ' '; // add space to ciphertext
            continue; // skip processing spaces
        }
        ciphertext += c;
    }
    return ciphertext;
}

string decrypt(string cipherCode, string inputkeyVig) {

    string plaintext = "";
    int keylen = inputkeyVig.length();
    int j = 0;  // index into key

    for (int i = 0; i < cipherCode.length(); i++) {
        char c = cipherCode[i];
        if (isalpha(c)) {
            c = toupper(c);  // convert to uppercase for simplicity
            int shift = inputkeyVig[j] - 'A';  // convert key letter to shift amount
            c = (((c - 'A' - shift) % 26) + 26) % 26 + 'A';  // apply shift and convert back to letter
            j = (j + 1) % keylen;  // move to next key letter
        }
        else if (c == ' ') {
            plaintext += ' '; // add space back to plaintext
            continue;
        }
        plaintext += c;
    }
    return plaintext;
}




void loginMenu() {
    system("cls");

    string lectorLinea;
    ifstream MyreadFile("portada.txt");
    while (getline(MyreadFile, lectorLinea)) {
        cout << lectorLinea << "\n";
    }
    MyreadFile.close();

    cout << R"(
                 ==========================
                         LOGIN MENU        
                 ==========================
                        Select an option:
                        (1) Create Account
                        (2) Log In
                        (3) Exit
                 ==========================)" << endl;


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
    cout << "==========================" << endl;
}

void insertText() {

    system("cls");
    cout << "==========================" << endl;
    cout << " INSERTE PALABRA A CIFRAR    " << endl;
    cout << "==========================" << endl;
    cout << "--> ";
}

void insertTextDecipher() {

    system("cls");
    cout << "==========================" << endl;
    cout << "INSERTE PALABRA A DESIFRAR   " << endl;
    cout << "==========================" << endl;
    cout << "--> ";
}

void keyinsertText() {

    system("cls");
    cout << "==========================" << endl;
    cout << "      INSERTE LLAVE   " << endl;
    cout << "==========================" << endl;
    cout << "--> ";
}

void userText() {

    system("cls");
    cout << "==========================" << endl;
    cout << "      INSERTE USERNAME   " << endl;
    cout << "==========================" << endl;
    cout << "--> ";
}

void passText() {

    system("cls");
    cout << "==========================" << endl;
    cout << "     INSERTE PASSWORD   " << endl;
    cout << "==========================" << endl;
    cout << "--> ";
}

void bruteforceMenu() {

    system("cls");
    cout << "==========================" << endl;
    cout << "DE CLICK A CUALQUIER TECLA   " << endl;
    cout << " PARA REALIZAR UN ATAQUE   " << endl;
    cout << "     DE FUERZA BRUTA   " << endl;
    cout << "==========================" << endl;

}

void tipollaveMenu() {

    system("cls");
    cout << "=======================================" << endl;
    cout << "        INSERTE TIPO DE LLAVE   " << endl;
    cout << "=======================================" << endl;
    cout << "Seleccione el tipo de cifrado" << endl;
    cout << "(1) Shift key, Ceasar Cipher (numerico)" << endl;
    cout << "(2) Vigenere Cipher (caracter)" << endl;
    cout << "--> ";
}


void outputcipher() {

    system("cls");
    cout << "==========================" << endl;
    cout << "  SU PALABRA CIFRADA ES    " << endl;
    cout << "==========================" << endl;
    cout << "--> ";
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
                system("pause");

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

                cout << "El username no existe, favor de crear uno" << endl;

                system("pause");

            }
            else {
                passText();
                cin >> password;

                bool result = VerifyPassword(username, password);

                if (result == false) {

                    cout << "Password incorrecto" << endl;
                    system("pause");
                   


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

                                outputcipher();

                                for (char c : cipherText) {

                                    cout << c;
                                }
                                cout << endl;
                                system("pause");//funcion para esperar key input para continuar



                                break;

                            }

                            case 2: {

                                string plaintext, key;

                                insertText();
                                getline(cin, plaintext);

                                keyinsertText();
                                getline(cin, key);

                                string ciphertext = encrypt(plaintext, key);

                                outputcipher();
                                cout << ciphertext << endl;
                                system("pause");//funcion para esperar key input para continuar


                                break;

                            }

                            case 3: {


                                insertText();

                                string input;
                                getline(cin, input); // read a line of input


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
                                outputcipher();
                                for (char d : ceasarText) {

                                    cout << d;
                                }


                                cout << endl;

                                system("pause");//funcion para esperar key input para continuar


                                break;
                            }

                            }

                            break;

                        }
                        case 2: {

                            //DECIPHERING CASE
                            cin.ignore();
                            insertTextDecipher();
                            string cipherCode;

                            getline(cin, cipherCode);

                            tipollaveMenu();

                            int keyType;
                            cin >> keyType;


                            if (keyType == 1) {



                                bruteforceMenu();
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
                            else if (keyType == 2) { //si el tipo de llave es de caracter se realiza el decrypt de vigenere 

                                cin.ignore();

                                keyinsertText();


                                string userinputkeyVig;

                                getline(cin, userinputkeyVig);

                                string vigOut = decrypt(cipherCode, userinputkeyVig);


                                cout << vigOut << endl;
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


    } while (choice != 3);
}