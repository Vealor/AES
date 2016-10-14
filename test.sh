javac *.java

java AES e key.txt plaintext.txt
java AES d key.txt plaintext.txt.enc
diff -i plaintext.txt plaintext.txt.enc.dec