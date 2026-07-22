package com.dvas;

import it.unisa.dia.gas.jpbc.Element;

public class sendToEN {
    public static class Send {
        private Element T_i; // 签名的 T_i 部分
        private Element V_i; // 随机生成的点 V_i
        private Message m_i; 
        private int id;

        public Send() {
        this.T_i = null;
        this.V_i = null;
        this.m_i = null;
        this.id = 0;
    }

        public Send(Element T_i, Element V_i, Message m_i, int id) {
            this.T_i = T_i;
            this.V_i = V_i;
            this.m_i = m_i;
            this.id = id;
        }

        public Element getT_i() {
            return T_i;
        }

        public Element getV_i() {
            return V_i;
        }

        public Message getm_i() {
            return m_i;
        }

        public int getId(){
            return id;
        }

        public void setT_i(Element T_i) {
            this.T_i =  T_i;
        }

        public void setV_i(Element V_i) {
            this.V_i = V_i;
        }
        
        public void setm_i(Message m_i) {
            this.m_i = m_i;
        }

        public void setid(int id) {
            this.id = id;
        }
    }
    
}
