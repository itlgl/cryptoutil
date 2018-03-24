package com.itlgl.cryptoutil.aes;

public class AESException extends Exception {
    public AESException(String msg) {
        super(msg);
    }

    public AESException(Exception e) {
        super(e);
    }
}
