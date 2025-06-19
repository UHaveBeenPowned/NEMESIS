# NEMESIS
This is NEMESIS, a program created for my TFM project. This program can stop the execution of Jigsaw implementing diferent tactics.

## venv configuration
Open a terminal and execute:
    
    $ powershell -ExecutionPolicy Bypass -File .\venv\Scripts\Activate.ps1

    $ py -m pip install -r requirements.txt

# RELEASE MODE
In order to ensure safety, the "RELEASE" variable found in "process.py" is set to false. This ensure that if any process complies with the constrains (like having to many processes alive) wont be killed and erase.
If you want to enable the kill functionality and the decrypt functionality. Set the "RELEASE" variable to "true".

# Decrypt key
In the class "Decryptor", ubicated in "aes.py", can be found a private variable called "self._key_b64". In the version of Jigsaw analized for this proyect, the base64 string is "OoIsAwwF23cICQoLDA0ODe==".

In other versions of Jigsaw this can change, so:

* The "self._key_b64" variable is empty, put the b64 key if its known.
* If the key its known but is in plain text, set the "self._plain_key" with the known key.
* If the key is unknown, do not set any variable.

**Note**: In the actual version, the decrypt functionality could not work if the algorithm use an IV for initialization. If this is your case, you can try to fork the proyect and try to implement it :)

# nemesis.exe
An "nemesis.exe" can be found in the folder "executable". This executable have the RELEASE mode activated and the decryption key setted to "OoIsAwwF23cICQoLDA0ODe==".

In order to compile your own NEMESIS. Open a terminal in the folder NEMESIS:

    $ pyinstaller --noconsole --onefile --name nemesis nemesis.py

A new folder called "dist" will appear. Inside the new "nemesis.exe" can be found.

**Note**: To comply this step, you must do the steps found in **"venv configuration"**.