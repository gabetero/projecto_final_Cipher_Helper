#include <iostream>
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
    ofstream fout(PASSWORD_FILE);
    if (fout) {
        fout << password;
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
    ofstream fout(USERNAME_FILE);
    if (fout) {
        fout << username;
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


void principalMenu() {

    cout << "+ ----------------- +\n";
    cout << "|   Escoja opcion   |\n";
    cout << "--------------------\n";
    cout << "|    (1) Cifrar     |\n";
    cout << "|    (2) Desifrar   |\n";
    cout << "|    (3) Exit       |\n";
    cout << "+ ----------------- +\n--> ";


}


string decryptRailFence(const string& encrypted, int key) {
    int len = encrypted.length();
    vector<vector<char>> rail(key, vector<char>(len, '.'));

    // Fill in rail fence with placeholder characters
    bool dir_down = false;
    int row = 0, col = 0;
    for (int i = 0; i < len; i++) {
        if (row == 0 || row == key - 1) {
            dir_down = !dir_down;
        }
        rail[row][col++] = '*'; // use * as a placeholder character
        if (dir_down) {
            row++;
        }
        else {
            row--;
        }
    }

    // Read encrypted message into rail fence
    int k = 0;
    row = 0, col = 0;
    for (int i = 0; i < len; i++) {
        if (row == 0 || row == key - 1) {
            dir_down = !dir_down;
        }
        if (rail[row][col] == '*') {
            rail[row][col] = encrypted[k++];
        }
        if (dir_down) {
            row++;
        }
        else {
            row--;
        }
        col++; // move to next column
    }

    // Read decrypted message from rail fence
    string decrypted = "";
    row = 0, col = 0;
    for (int i = 0; i < len; i++) {
        if (row == 0 || row == key - 1) {
            dir_down = !dir_down;
        }
        if (rail[row][col] != '*') {
            decrypted += rail[row][col];
        }
        if (dir_down) {
            row++;
        }
        else {
            row--;
        }
        col++; // move to next column
    }

    return decrypted;
}

int main() {
    // Revisa si el file con el password existe. De no existir le pide al usuario entrar un password nuevo.
    int authLoop = 0;
    while (authLoop < 1)
    {

        if (ifstream(PASSWORD_FILE)) {

        }
        else {
            cout << "Password no encontrado. Entra un nuevo password: ";
            string password;
            cin >> password;
            string hashed_password = HashPassword(password);
            SavePassword(hashed_password);
        }

        //  Revisa si el file con el username existe. De no existir se debe entrar un nombre de usuario nuevo.
        if (ifstream(USERNAME_FILE)) {

        }
        else {
            cout << "Username no encontrado. Porfavor entra un nuevo username: ";
            string username;
            cin >> username;
            SaveUsername(username);
        }

        // Usuario entra username y password.
        string username, password;
        cout << "Entre su username: ";
        cin >> username;
        cout << "Entre su password: ";
        cin >> password;
        string hashed_input_password = HashPassword(password);




        string saved_username = ReadUsername();
        string saved_password = ReadPassword();
        if (saved_username == username && saved_password == hashed_input_password) {
            authLoop++;
            int choicemenuPrincipal = 0;


            while (choicemenuPrincipal < 5) {

                principalMenu();

                cin >> choicemenuPrincipal;

                system("cls");

                switch (choicemenuPrincipal) {

                case 1:
                {
                    cout << "---------------------------------------------\n";
                    cout << "|     Escoja su metodo de cifrado           |\n";
                    cout << "|        (1) Shift Cipher                   |\n";
                    cout << "|        (2) Rail Fence Cipher              |\n";
                    cout << "|        (3) Ceasar Cipher                  |\n";
                    cout << "---------------------------------------------\n--> ";

                    int cipherChoice;
                    cin >> cipherChoice;
                    cin.ignore(); //se utiliza para limpiar el input buffer para que se pueda utilizar getline
                    system("cls");

                    cout << "---------------------------------------------\n";
                    cout << "|                                           |\n";
                    cout << "|     Inserte palabra que desea cifrar      |\n";
                    cout << "|                                           |\n";
                    cout << "---------------------------------------------\n--> ";

                    string input;
                    getline(cin, input); // read a line of input

                    int key;

                    system("cls");

                    cout << "+ --------------------------------------------- +\n";
                    cout << "|     Inserte su llave (debe ser numerica)      |\n";
                    cout << "+ --------------------------------------------- +\n--> ";


                    cin >> key;


                    vector<char> cipherText;
                    vector<char> bruteForce;


                    switch (cipherChoice) {

                    case 1: {

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


                        // Initialize rail fence
                        int len = input.length();
                        vector<vector<char>> rail(key, vector<char>(len, '.'));

                        // Fill in rail fence with message

                        bool dir_down = false;

                        int row = 0, col = 0;

                        for (int i = 0; i < len; i++) {

                            if (row == 0 || row == key - 1) {

                                dir_down = !dir_down;
                            }
                            rail[row][col++] = input[i];

                            if (dir_down) {

                                row++;
                            }
                            else {
                                row--;
                            }
                        }

                        // Read encrypted message from rail fence
                        string encrypted = "";

                        for (int i = 0; i < key; i++) {

                            for (int j = 0; j < len; j++) {

                                if (rail[i][j] != '.') {

                                    encrypted += rail[i][j];
                                }
                            }
                        }
                        system("cls");
                        cout << "                    + ------------------------------------------------------------- + " << endl;
                        cout << "                    |  Dale click a cualquier tecla para proceder al menu principal |" << endl;
                        cout << "                    |                   Recuerde guardar su cifrado                 | " << endl;
                        cout << "                    + ------------------------------------------------------------- +" << endl;
                        cout << "\n                               Su palabra cifrada es: ";
                        cout << encrypted << endl;

                        system("pause");//funcion para esperar key input para continuar

                        system("cls");

                        break;

                    }

                    case 3: {

                        system("cls");

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
                    }

                    break;

                }
                case 2: {

                    cin.ignore();

                    cout << "Inserte codigo a desifrar" << endl;
                    string cipherCode;

                    getline(cin, cipherCode);
                    int contador = 0;

                    while (contador <= 1) {//se utiliza loop bool para validacion de user input(y/n)

                        cout << endl << "Sabe usted la llave de su cifrado? (Y/N)\n--->";

                        char userInput;

                        cin >> userInput;



                        if (toupper(userInput) == 'Y') {

                            contador = 2;//salir del loop de validacion de input
                            cout << "Favor de insertar su llave";
                            int userinputKey;
                            cin >> userinputKey;

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
                    system("pause");
                    system("cls");

                    break;

                }


                }




            }

        }
        else {
            cout << "Autenticacion fallida!" << endl;
            cout << "Intente de nuevo" << endl;
            system("pause");
            system("cls");
        }

    }
}