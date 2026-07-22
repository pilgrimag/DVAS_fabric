package com.dvas;

 // 消息类
 public class Message {
    private String m;
    private String omega;

    public Message(String m, String omega) {
        this.m = m;
        this.omega = omega;
    }

    public String getM() {
        return m;
    }

    public String getOmega() {
        return omega;
    }

    public void setM(String m){
        this.m = m;
    }
}