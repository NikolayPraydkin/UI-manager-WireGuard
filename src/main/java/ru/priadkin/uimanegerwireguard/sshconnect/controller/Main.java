package ru.priadkin.uimanegerwireguard.sshconnect.controller;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;
import ru.priadkin.uimanegerwireguard.sshconnect.domain.SSH;
import ru.priadkin.uimanegerwireguard.sshconnect.domain.Status;

import java.io.*;
import java.util.*;
import java.util.stream.Stream;

@RestController
@RequestMapping("/")
@Slf4j
public class Main {

    private final SSH ssh;
    private final Map<UUID, Session> sessions = new HashMap<>();

    public Main(SSH ssh) {
        this.ssh = ssh;
    }

    @GetMapping("/connectSSHByPassword")
    public String connectSSHByPassword(@RequestParam(name = "host") String host,
                                       @RequestParam(name = "port", required = false) Integer port,
                                       @RequestParam(name = "user") String user,
                                       @RequestParam(name = "password") String password
    ) {
        try {
            Session session = ssh.connectByPassword(host, port, user, password);
            UUID uuid = UUID.randomUUID();
            sessions.put(uuid, session);
            return uuid.toString();
        } catch (Exception e) {
            log.error(e.getMessage());
            return "Session not saved, try again!";
        }

    }

    @DeleteMapping("/deleteSSHConnectionByUUID")
    public String connectSSHByPassword(@RequestParam(name = "uuid") UUID uuid) {
        try {
            sessions.get(uuid).disconnect();
            Session remove = sessions.remove(uuid);
            return remove != null ? "Successfully disconnect and deleted session" : "session does not exists";
        } catch (Exception e) {
            log.error(e.getMessage());
            return "Session not deleted, try again!";
        }

    }

    @DeleteMapping("/deleteAllSSHConnection")
    public String deleteAllSSHConnection() {
        try {
            sessions.values().forEach(Session::disconnect);
            sessions.clear();
            return "Successfully disconnect and deleted session";
        } catch (Exception e) {
            log.error(e.getMessage());
            return "Sessions not deleted, try again!";
        }

    }

    @GetMapping("/getAllSSHConnection")
    public Map<UUID,Session> getAllSSHConnection() throws Exception {
        try {
            return sessions;
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        throw new Exception("No one session didn't find");
    }

    @DeleteMapping("/dropSessionByHost")
    public String dropSessionByHost(@RequestParam(name = "host") String host) throws Exception {
        try {
            List<UUID> keysForDelete = new ArrayList<>();
            sessions.forEach((k, v) -> {
                if (v.getHost().equals(host)) {
                    v.disconnect();
                    keysForDelete.add(k);
                }
            });
            keysForDelete.forEach(sessions::remove);
            return "Deleted session by host " + host + " " + keysForDelete;
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        throw new Exception("No one session deleted by host " + host);
    }
    @GetMapping("/checkwireguard")
    public Status checkWiregurd(@RequestParam(name = "host") String host) throws Exception {

        Status status = new Status();
        sessions.forEach((k, v) -> {
            ChannelExec channel = null;
            if (v.getHost().equals(host)) {
                try {
                    channel = (ChannelExec) v.openChannel("exec");
                    channel.setCommand("dpkg -s wireguard");
                    InputStream in=channel.getInputStream();

                    channel.connect();

                    byte[] tmp=new byte[1024];
                    StringBuilder builder = new StringBuilder();
                    while(true){
                        while(in.available()>0){
                            int i=in.read(tmp, 0, 1024);
                            if(i<0)break;
                            builder.append(new String(tmp, 0, i));
                        }
                        if(channel.isClosed()){
                            if(in.available()>0) continue;
                            System.out.println("exit-status: "+channel.getExitStatus());
                            break;
                        }
                        try{Thread.sleep(1000);}catch(Exception ee){}
                    }
                    String statusWG = builder.toString();
                    if(statusWG.contains("Status: install ok")){
                        status.setInstaledWireguard(true);
                    }
                    status.setMessage(statusWG);

                    channel.disconnect();

                } catch (JSchException e) {
                    throw new RuntimeException(e);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        });
        if (sessions.size() == 0) {
            status.setMessage("No one session is connected");
        }
        return status;
    }

    @GetMapping("/powerOff")
    public String powerOff(@RequestParam(name = "host") String host) throws Exception {
        try {
            sessions.forEach((k, v) -> {
                if (v.getHost().equals(host)) {
                    ChannelExec channel = null;
                    try {
                        channel = (ChannelExec) v.openChannel("exec");

                        ByteArrayOutputStream responseStream = new ByteArrayOutputStream();
                        channel.setOutputStream(responseStream);

                        BufferedReader stdError = new BufferedReader(new
                                InputStreamReader(channel.getErrStream()));
                        channel.setCommand("echo poker | sudo -S poweroff");

                        channel.connect();

                        while (channel.isConnected()) {
                            Thread.sleep(3000);
                        }

                        String responseString = responseStream.toString();
                        boolean ready = stdError.ready();
                        String s = stdError.readLine();
                        channel.getOutputStream().write("poker".getBytes());
                        System.out.println(responseString);


                    } catch (JSchException e) {
                        throw new RuntimeException(e);
                    } catch (InterruptedException e) {
                        throw new RuntimeException(e);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
            });

            return "Power off" + host;
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        throw new Exception("Not power off by host " + host);
    }

}
