package ru.priadkin.uimanegerwireguard.sshconnect.domain;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import org.apache.commons.io.IOUtils;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.stream.Collectors;

@Component
public class SSH {

    public  void listFolderStructure(String username, String password,
                                           String host, int port, String command) throws Exception {

        Session session = null;
        ChannelExec channel = null;

        try {
            String[] args = new String[] {"/bin/bash", "-c", "ssh-keygen"};
            Process proc = new ProcessBuilder(args).start();

            int available = proc.getInputStream().available();

            byte[] bytes = proc.getInputStream().readNBytes(available);

            System.out.println(new String(bytes));

            try (BufferedWriter bufferedWriter = proc.outputWriter()){
                bufferedWriter.write("good");
            }
//            proc.outputWriter().write("good");
//            proc.outputWriter().flush();

//            Thread.sleep(3000);
            int available2 = proc.getInputStream().available();

            byte[] bytes2 = proc.getInputStream().readNBytes(available2);
            System.out.println(new String(bytes2));
            BufferedReader bufferedReader = proc.inputReader();
            while (bufferedReader.ready()){
            String s1s21 = bufferedReader.readLine();
                System.out.println(s1s21);
            }
            String result = IOUtils.toString(proc.getInputStream(), StandardCharsets.UTF_8);
            BufferedReader stdInput = new BufferedReader(new
                    InputStreamReader(proc.getInputStream()));

            InputStream inputStream = proc.getInputStream();
            BufferedWriter stdOut = new BufferedWriter(new
                    OutputStreamWriter(proc.getOutputStream()));

            BufferedReader stdError = new BufferedReader(new
                    InputStreamReader(proc.getErrorStream()));

// Read the output from the command
            System.out.println("Here is the standard output of the command:\n");
            String s = null;
//            while ((s = stdInput.readLine()) != null) {
            while (inputStream.available() != 0) {
                System.out.println(inputStream.readAllBytes().toString());
                stdOut.write("test");
            }

// Read any errors from the attempted command
            System.out.println("Here is the standard error of the command (if any):\n");
            while ((s = stdError.readLine()) != null) {
                System.out.println(s);
            }

//            session = new JSch().getSession(username, host, port);

            JSch jSch = new JSch();
            String collect = Files.readAllLines(Paths.get("test")).stream()
                    .filter(l ->
                            !l.contains("BEGIN") && !l.contains("END")
                    )
                    .collect(Collectors.joining());
//            jSch.addIdentity("hello", "hello");
            jSch.addIdentity("hello");
//            session = jSch.getSession(username, host, port);
            session = jSch.getSession(host);
//            session.setPassword(password);
//            String test = Files.readString(Paths.get("test"));
//            session.setPassword(Files.readString(Paths.get("test")));
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect();

            channel = (ChannelExec) session.openChannel("exec");
            channel.setCommand(command);
            ByteArrayOutputStream responseStream = new ByteArrayOutputStream();
            channel.setOutputStream(responseStream);
            channel.connect();

            while (channel.isConnected()) {
                Thread.sleep(100);
            }

            String responseString = responseStream.toString();
            System.out.println(responseString);
        } finally {
            if (session != null) {
                session.disconnect();
            }
            if (channel != null) {
                channel.disconnect();
            }
        }
    }

    public Session connectByPassword(String host, Integer port, String user, String password) throws JSchException {
        JSch jSch = new JSch();
        Session session = jSch.getSession(user, host, Optional.ofNullable(port).orElse(22));
        session.setPassword(password);
        session.setConfig("StrictHostKeyChecking", "no");
        session.connect();
        return session;
    }
}
