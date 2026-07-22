package com.dvas;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import it.unisa.dia.gas.jpbc.Element;

public class SensorKeyPair {
    private Element R_i; // 传感器节点的密钥对中的私钥
    private Element u_i; // 传感器节点的密钥对中的公钥
    private Element U_i;
    int id;


    public SensorKeyPair(Element R_i, Element u_i, Element U_i,  int sensorID) {
        this.R_i = R_i;
        this.u_i = u_i;
        this.U_i = U_i;
        this.id = sensorID;
    }

    // 获取 R_i
    public Element getR_i() {
        return R_i;
    }

    // 获取 u_i
    public Element getu_i() {
        return u_i;
    }

     // 获取 u_i
     public Element getU_i() {
        return U_i;
    }

     // 获取 id
     public int getid() {
        return id;
    }
}
