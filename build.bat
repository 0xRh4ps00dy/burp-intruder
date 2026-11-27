@echo off
set "JAVA_BIN=C:\Program Files\RedHat\java-1.8.0-openjdk-1.8.0.492-1\bin"
echo Cleaning build directories...
if exist build\classes rmdir /s /q build\classes
mkdir build\classes

echo Compiling Java source files...
"%JAVA_BIN%\javac" -encoding UTF-8 -cp "burp-api.jar;lib\dec-0.1.2.jar" -d build\classes src\main\java\burp\*.java
if %errorlevel% neq 0 (
    echo Compilation failed!
    exit /b %errorlevel%
)

echo Extracting dependencies...
cd build\classes
"%JAVA_BIN%\jar" xf ..\..\lib\dec-0.1.2.jar
if %errorlevel% neq 0 (
    echo Extraction of dec-0.1.2.jar failed!
    cd ..\..
    exit /b %errorlevel%
)
cd ..\..

echo Copying default grep terms...
if exist default_grep_terms.txt copy /y default_grep_terms.txt build\classes\

echo Packaging burp-intruder.jar...
if exist burp-intruder.jar del /f burp-intruder.jar
"%JAVA_BIN%\jar" cf burp-intruder.jar -C build\classes burp -C build\classes org -C build\classes default_grep_terms.txt
if %errorlevel% neq 0 (
    echo Packaging failed!
    exit /b %errorlevel%
)

echo Build successful! burp-intruder.jar generated.
