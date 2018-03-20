# Password Tools

This project provides a reusable secure password hashing library.

The jar file created by this library has no 3rd party dependencies, only a Java 7 runtime (e.g. OpenJDK, Oracle, IBM).

## Usage

The entry point for usage is the [PasswordEncoder](https://github.com/STEP-Cloud/FGC_PasswordTools/blob/master/src/main/java/uk/org/cambsfire/security/PasswordEncoder.java) class. See the class javadoc for full details and the [tests](https://github.com/STEP-Cloud/FGC_PasswordTools/blob/master/src/test/java/uk/org/cambsfire/security/PasswordEncoderTest.java).

The basic usage is:

```
String encodedHashedPassword = uk.org.cambsfire.security.PasswordEncoder.encode("rawPassword");
boolean passwordsMatch = uk.org.cambsfire.security.PasswordEncoder.matches("rawPassword", encodedHashedPassword);
```

## Building 

    .\mvnw install
