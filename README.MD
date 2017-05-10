# Password Tools

This project provides a reusable secure password hashing library.

## Usage

The entry point for usage is the [PasswordEncoder](https://github.com/STEP-Cloud/FGC_PasswordTools/blob/master/src/main/java/uk/org/cambsfire/security/PasswordEncoder.java) class. See the class javadoc for full details and the [tests](https://github.com/STEP-Cloud/FGC_PasswordTools/blob/master/src/test/java/uk/org/cambsfire/security/PasswordEncoderTest.java).

The basic usage is:

##

```
String encodedHashedPassword = uk.org.cambsfire.security.encode("rawPassword");
boolean passwordsMatch = PasswordEncoder.matches("rawPassword", encodedHashedPassword);
```


