package ru.priadkin.uimanegerwireguard.sshconnect.controller;

import com.jcraft.jsch.Session;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;
import ru.priadkin.uimanegerwireguard.sshconnect.domain.SSH;

import java.util.*;

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

}
