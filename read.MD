### GEN Cert 
```bash
cd $JAVA_1_11_HOME/bin
```

```bash
./keytool -genkey -alias bootsecurity -storetype PKCS12 -keyalg RSA -keysize 2048 -keystore bootsecurity.p12 -validity 3650
```


cp to resource folder.
