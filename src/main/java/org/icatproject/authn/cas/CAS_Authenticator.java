/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.icatproject.authn.cas;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.util.Map;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;

import javax.ejb.Remote;
import javax.ejb.Stateless;
import javax.annotation.PostConstruct;
import javax.json.Json;
import javax.json.stream.JsonGenerator;


import org.apache.log4j.Logger;
import org.icatproject.authentication.Authenticator;
import org.icatproject.authentication.Authentication;
import org.icatproject.core.IcatException;
import org.icatproject.utils.CheckedProperties;
import org.icatproject.utils.CheckedProperties.CheckedPropertyException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;

/**
 *
 * @author elz24996
 */
@Stateless(mappedName = "org.icatproject.authn_cas.CAS_Authenticator")
@Remote
public class CAS_Authenticator implements Authenticator  {
    
    private static final Logger logger = Logger.getLogger(CAS_Authenticator.class);
    private String casServer;
    
    @PostConstruct
    private void init() {
        File f = new File("authn_cas.properties");
        CheckedProperties props = new CheckedProperties();
        try {
            props.loadFromFile("authn_cas.properties");
            this.casServer = props.getString("casServer").trim();
            logger.info("casServer: " + casServer);
        } catch(CheckedPropertyException e) {
            logger.fatal(e.getMessage());
            throw new IllegalStateException(e.getMessage());
        }  
    }
    
    @Override
    public Authentication authenticate(Map<String, String> credentials, String remoteAddr) throws IcatException {
        String ticket = credentials.get("ticket");
        String service = credentials.get("service");
        String username = "";
        String failure = "";
        
        try {
            String url = casServer + "/serviceValidate?ticket=" + URLEncoder.encode(ticket, "UTF-8") + "&service=" + URLEncoder.encode(service, "UTF-8");
            
            String xml = sendGet(url);
            
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            ByteArrayInputStream input = new ByteArrayInputStream(xml.getBytes("UTF-8"));
            Document document = builder.parse(input);
            
            XPath xPath =  XPathFactory.newInstance().newXPath();
            username = (String) xPath.compile("serviceResponse/authenticationSuccess/user").evaluate(document);
            failure = (String) xPath.compile("serviceResponse/authenticationFailure").evaluate(document).trim();
            
        } catch(Exception e){
            logger.fatal(e.getMessage());
        }
        
        if(!username.equals("") && failure.equals("")){
            return new Authentication(username, "cas");
        } else {
            if(!failure.equals("")){
                throw new IcatException(IcatException.IcatExceptionType.SESSION, "Could not autheticate with CAS server - " + failure);
            } else {
                throw new IcatException(IcatException.IcatExceptionType.SESSION, "Could not autheticate with CAS server.");
            }
        } 
    }
    
    @Override
    public String getDescription() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        JsonGenerator gen = Json.createGenerator(baos);
        gen.writeStartObject().writeStartArray("keys");
        gen.writeStartObject().write("name", "service").writeEnd();
        gen.writeStartObject().write("name", "ticket").writeEnd();
        gen.writeEnd().writeEnd().close();
        return baos.toString();
    }
    
    private String sendGet(String url) throws Exception {
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setRequestMethod("GET");

        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String inputLine;
        StringBuffer response = new StringBuffer();

        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();

        return response.toString();
    }

}