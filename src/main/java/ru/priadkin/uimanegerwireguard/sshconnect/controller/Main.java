package ru.priadkin.uimanegerwireguard.sshconnect.controller;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.ChannelShell;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import lombok.extern.slf4j.Slf4j;
import net.sf.expectit.Expect;
import net.sf.expectit.ExpectBuilder;
import net.sf.expectit.MultiResult;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import ru.priadkin.uimanegerwireguard.sshconnect.domain.SSH;
import ru.priadkin.uimanegerwireguard.sshconnect.domain.Status;
import ru.priadkin.uimanegerwireguard.sshconnect.domain.StatusWG;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static net.sf.expectit.filter.Filters.removeColors;
import static net.sf.expectit.filter.Filters.removeNonPrintable;
import static net.sf.expectit.matcher.Matchers.anyOf;
import static net.sf.expectit.matcher.Matchers.contains;
import static net.sf.expectit.matcher.Matchers.regexp;

@RestController
@RequestMapping("/")
@Slf4j
public class Main {

    private final SSH ssh;
    private final Map<UUID, Session> sessions = new HashMap<>();

    public Main(SSH ssh) {
        this.ssh = ssh;
    }

    @GetMapping("/hello")
    public String geth(){
        return "hello";
    }
    @GetMapping("/connectSSHByPassword")
    public ResponseEntity<String> connectSSHByPassword(@RequestParam(name = "host") String host,
                                                      @RequestParam(name = "port", required = false) Integer port,
                                                      @RequestParam(name = "user") String user,
                                                      @RequestParam(name = "password") String password
    ) {
        try {
            Session session = ssh.connectByPassword(host, port, user, password);
            UUID uuid = UUID.randomUUID();
            sessions.put(uuid, session);
            return ResponseEntity.ok(uuid.toString());
        } catch (Exception e) {
            log.error(e.getMessage());
            return ResponseEntity.status(HttpStatus.GATEWAY_TIMEOUT).body("Session not saved, try again!");
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
    public Map<UUID, Session> getAllSSHConnection() throws Exception {
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
    public StatusWG checkWiregurd(@RequestParam(name = "host") String host) {

        StatusWG status = new StatusWG();
        sessions.forEach((k, v) -> {
            ChannelExec channel = null;
            if (v.getHost().equals(host)) {
                try {
                    channel = (ChannelExec) v.openChannel("exec");
                    channel.setCommand("dpkg -s wireguard");
                    InputStream in = channel.getInputStream();

                    channel.connect();

                    byte[] tmp = new byte[1024];
                    StringBuilder builder = new StringBuilder();
                    int countWait = 3;
                    while (true) {
                        while (in.available() > 0) {
                            int i = in.read(tmp, 0, 1024);
                            if (i < 0) break;
                            builder.append(new String(tmp, 0, i));
                        }
                        if (channel.isClosed()) {
                            if (in.available() > 0) continue;
                            System.out.println("exit-status: " + channel.getExitStatus());
                            break;
                        }
                        if(countWait == 0){
                            break;
                        }
                        try {
                            Thread.sleep(1000);
                            countWait--;
                        } catch (Exception ee) {
                            log.error("Some error when waiting response {}", ee.getMessage());
                        }
                    }
                    String statusWG = builder.toString();
                    if (statusWG.contains("Status: install ok")) {
                        status.setInstaledWireguard(true);
                    }
                    status.setMessage(statusWG);

                } catch (JSchException | IOException e) {
                    throw new RuntimeException(e);
                }finally {
                    if (channel != null) {
                        channel.disconnect();
                    }
                }
            }
        });
        if (sessions.size() == 0) {
            status.setMessage("No one session is connected");
        }
        return status;
    }

    @GetMapping("/installwireguard")
    public StatusWG installwg(@RequestParam(name = "host") String host, @RequestParam(name = "supass") String supass) {
        StatusWG status = new StatusWG();
        sessions.forEach((k, v) -> {
            ChannelExec channel = null;
            if (v.getHost().equals(host)) {
                try {
                    channel = (ChannelExec) v.openChannel("exec");
                    channel.setCommand(String.format("echo %s | sudo -S apt install -y wireguard", supass));
                    InputStream in = channel.getInputStream();
                    InputStream errStream = channel.getErrStream();

                    channel.connect();
                    StringBuilder builder = new StringBuilder();
                    while (true) {
                        while (in.available() > 0) {
                            byte[] tmp = new byte[in.available()];
                            int i = in.read(tmp, 0, in.available());
                            if (i < 0) break;
                            builder.append(new String(tmp, 0, i));
                        }
                        while (errStream.available() > 0) {
                            byte[] tmper = new byte[errStream.available()];
                            int i = errStream.read(tmper, 0, errStream.available());
                            if (i < 0) break;
                            builder.append(new String(tmper, 0, i));
                        }
                        if (channel.isClosed()) {
                            if (in.available() > 0) continue;
                            System.out.println("exit-status: " + channel.getExitStatus());
                            break;
                        }
                        try {
                            Thread.sleep(1000);
                        } catch (Exception ee) {
                        }
                    }
                    String statusWG = builder.toString();
                    if (statusWG.contains("Уже установлен пакет wireguard") || statusWG.contains("Настраивается пакет wireguard ")) {
                        status.setInstaledWireguard(true);
                    }
                    status.setMessage(statusWG);

                } catch (JSchException e) {
                    throw new RuntimeException(e);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }finally {
                    if (channel != null) {
                        channel.disconnect();
                    }
                }
            }
        });
        if (sessions.size() == 0) {
            status.setMessage("No one session is connected");
        }
        return status;
    }

    @GetMapping("/removewireguard")
    public StatusWG removewg(@RequestParam(name = "host") String host, @RequestParam(name = "supass") String supass) {
        StatusWG status = new StatusWG();
        sessions.forEach((k, v) -> {
            ChannelExec channel = null;
            if (v.getHost().equals(host)) {
                try {
                    channel = (ChannelExec) v.openChannel("exec");
                    channel.setCommand(String.format("echo %s | sudo -S apt --purge remove -y wireguard; echo %s | sudo apt autoclean && sudo apt autoremove -y",supass,supass));

                    InputStream in = channel.getInputStream();
                    InputStream errStream = channel.getErrStream();

                    channel.connect();
                    StringBuilder builder = new StringBuilder();
                    while (true) {
                        while (in.available() > 0) {
                            byte[] tmp = new byte[in.available()];
                            int i = in.read(tmp, 0, in.available());
                            if (i < 0) break;
                            builder.append(new String(tmp, 0, i));
                        }
                        while (errStream.available() > 0) {
                            byte[] tmper = new byte[errStream.available()];
                            int i = errStream.read(tmper, 0, errStream.available());
                            if (i < 0) break;
                            builder.append(new String(tmper, 0, i));
                        }
                        if (channel.isClosed()) {
                            if (in.available() > 0) continue;
                            System.out.println("exit-status: " + channel.getExitStatus());
                            break;
                        }
                        try {
                            Thread.sleep(1000);
                        } catch (Exception ee) {
                        }
                    }
                    String statusWG = builder.toString();
                    if (statusWG.contains("Уже установлен пакет wireguard") || statusWG.contains("Настраивается пакет wireguard ")) {
                        status.setInstaledWireguard(true);
                    }
                    status.setMessage(statusWG);



                } catch (JSchException e) {
                    throw new RuntimeException(e);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }finally {
                    if (channel != null) {
                        channel.disconnect();
                    }
                }
            }
        });
        if (sessions.size() == 0) {
            status.setMessage("No one session is connected");
        }
        return status;
    }

    @GetMapping("/generatekeyswg")
    public Status generateKeysWG(@RequestParam(name = "host") String host,
                                 @RequestParam(name = "keyname", required = false) String keyname,
                                 @RequestParam(name = "overridekey", required = false) boolean overridekey,
                                 @RequestParam(name = "supass") String supass
    ) {
        String prefixNameKeys;
        if (keyname == null) {
            prefixNameKeys = UUID.randomUUID().toString();
        } else {
            prefixNameKeys = keyname;
        }
        final String fullNamePrivateKey = prefixNameKeys + "_privatekey";
        String command = String.format("wg genkey | tee /etc/wireguard/%s_privatekey | wg pubkey | tee /etc/wireguard/%s_publickey", prefixNameKeys, prefixNameKeys);
        Status status = new Status();
        sessions.forEach((k, v) -> {
            ChannelShell channel = null;
            if (v.getHost().equals(host)) {
                try {
                    channel = (ChannelShell) v.openChannel("shell");
                    channel.connect();
                    StringBuilder builder = new StringBuilder();
                    try (
                            Expect expect = new ExpectBuilder()
                                    .withTimeout(2, TimeUnit.SECONDS)
                                    .withOutput(channel.getOutputStream())
                                    .withInputs(channel.getInputStream(), channel.getExtInputStream())
                                    .withEchoInput(builder)
                                    .withEchoOutput(builder)
                                    .withInputFilters(removeColors(), removeNonPrintable())
                                    .withExceptionOnFailure()
                                    .build()
                    ) {

                        expect.sendLine("sudo su");
                        Thread.sleep(100);
                        expect.expect(regexp(".*"));
                        expect.sendLine(supass);
                        Thread.sleep(100);
                        expect.expect(regexp(".*"));
                        expect.sendLine("cd /etc/wireguard");
                        Thread.sleep(100);
                        expect.expect(regexp(".*"));
                        expect.sendLine("ls");
                        Thread.sleep(500);
                        if (builder.toString().contains(fullNamePrivateKey) && !overridekey) {
                            throw new Exception("Key with name " + fullNamePrivateKey + " already exists");
                        } else {
                            expect.sendLine(command);
                            Thread.sleep(100);
                            expect.expect(regexp(".*"));
                            Thread.sleep(3000);
                        }
                    } catch (InterruptedException e) {
                        throw new RuntimeException(e);
                    }

                    String statusWG = builder.toString();

                    status.setMessage(statusWG);


                } catch (JSchException e) {
                    throw new RuntimeException(e);
                } catch (Exception e) {
                    status.setMessage(e.getMessage());
                }finally {
                    if (channel != null) {
                        channel.disconnect();
                    }
                }
            }
        });
        if (sessions.size() == 0) {
            status.setMessage("No one session is connected");
        }
        return status;
    }

    @GetMapping("/createwg0conf")
    public Status createwg0conf(@RequestParam(name = "host") String host
            , @RequestParam(name = "namekey", required = false, defaultValue = "wg") String namekey
            , @RequestParam(name = "ip", required = false, defaultValue = "") String ip
            , @RequestParam(name = "overwriteexistingconf", defaultValue = "false") boolean overwrite,
                                @RequestParam(name = "supass") String supass

    ) {
        Status status = new Status();
        sessions.forEach((k, v) -> {
            ChannelShell channel;
            if (v.getHost().equals(host)) {
                try {
                    channel = (ChannelShell) v.openChannel("shell");
                    ChannelSftp sftpChannel = (ChannelSftp) v.openChannel("sftp");
                    sftpChannel.connect();
                    channel.connect();
                    StringBuilder builderOut = new StringBuilder();
                    StringBuilder builderIn = new StringBuilder();
                    try (Expect expect = new ExpectBuilder()
                            .withOutput(channel.getOutputStream())
                            .withInputs(channel.getInputStream(), channel.getExtInputStream())
                            .withEchoInput(builderIn)
                            .withEchoOutput(builderOut)
                            .withInputFilters(removeColors(), removeNonPrintable())
                            .withExceptionOnFailure()
                            .build()) {
                        boolean isTmpFolderCreated;
                        String tmpFolder = getUniqFolderName();
                        //check exist wg0.conf
                        boolean exists = false;
                        try {
                            makeTmpDir(tmpFolder, v.getUserName(), expect);
                            upgradeToSU(expect, supass);
                            goToWGFolder(expect);
                            moveFromWGFolderToOutputStream(expect, sftpChannel, v.getUserName(), tmpFolder);
                            exists = true;
                        } catch (Exception e) {
                        }
                        removeTmpDir(tmpFolder, v.getUserName(), expect);
                        if (!exists || overwrite) {
                            String getipinterface = getipinterface(v.getHost());
                            ByteArrayInputStream stream = prepareRawWG0ConfFile(getKeyByName(builderIn, expect, namekey.isBlank() ? "wg" : namekey, true), ip.isBlank() ? "" : ip, getipinterface);
                            downgradeToUser(expect, v.getUserName(), v.getUserInfo().getPassword());
                            isTmpFolderCreated = makeTmpDir(tmpFolder, v.getUserName(), expect);
                            if (isTmpFolderCreated) {
                                sftpChannel.put(stream, "/home/" + v.getUserName() + "/" + tmpFolder + "/wg0.conf");

                                upgradeToSU(expect, supass);

                                moveFromTmpFolderToWGFolder(expect, v.getUserName(), tmpFolder);

                                removeTmpDir(tmpFolder, v.getUserName(), expect);

                            } else {
                                throw new Exception("TmpFolder not created!");
                            }
                        } else {
                            status.setMessage("Wg0.conf already exist and override Not allowed!");
                        }
                        status.setMessage("ok");
                    } finally {
                        channel.disconnect();
                        sftpChannel.disconnect();
                    }
                } catch (Exception e) {
                    status.setMessage(e.getMessage());
                }
            }
        });
        return status;
    }

    @GetMapping("/getwg0conf")
    public Status getwg0conf(@RequestParam(name = "host") String host, @RequestParam(name = "suPass") String suPass) {
        Status status = new Status();
        sessions.forEach((k, v) -> {
            if (v.getHost().equals(host)) {
                try {
                    ChannelShell channel = (ChannelShell) v.openChannel("shell");
                    ChannelSftp sftpChannel = (ChannelSftp) v.openChannel("sftp");
                    sftpChannel.connect();
                    channel.connect();
                    StringBuilder builderIn = new StringBuilder();
                    StringBuilder builderOut = new StringBuilder();
                    Expect expect = getExpect(channel, builderIn, builderOut);
                    try {
                        String wg0AsString = getWG0AsString(v, sftpChannel, expect, suPass);
                        status.setMessage(wg0AsString);
                    } finally {
                        expect.close();
                        channel.disconnect();
                        sftpChannel.disconnect();
                    }
                } catch (Exception e) {
                    System.out.println(e.getMessage());
                }
            }
        });
        return status;
    }

    @GetMapping("/addPeerToWg0")
    public Status addpeertowg0(@RequestParam(name = "host") String host,
                               @RequestParam(name = "name") String name,
                               @RequestParam(name = "supass") String supass
    ) {
        Status status = new Status();
        sessions.forEach((k, v) -> {
            if (v.getHost().equals(host)) {
                try {
                    ChannelShell channel = (ChannelShell) v.openChannel("shell");
                    ChannelSftp sftpChannel = (ChannelSftp) v.openChannel("sftp");
                    sftpChannel.connect();
                    channel.connect();
                    StringBuilder builderIn = new StringBuilder();
                    StringBuilder builderOut = new StringBuilder();
                    Expect expect = getExpect(channel, builderIn, builderOut);
                    try {
                        addPeerToWg0Conf(v, expect, channel, sftpChannel, builderIn, name, supass);
                        // todo:check ipforwarding
                        enableIPForwarding(expect, builderIn);
                        restart(expect,builderIn, v.getUserInfo().getPassword());
                    } finally {
                        expect.close();
                        channel.disconnect();
                        sftpChannel.disconnect();
                    }
                } catch (Exception e) {
                    System.out.println(e.getMessage());
                }
            }
        });
        return status;
    }

    private boolean addPeerToWg0Conf(Session session, Expect expect, ChannelShell channel, ChannelSftp sftpChannel, StringBuilder builder, String name, String suPass) throws Exception {
        String wg0AsString = getWG0AsString(session, sftpChannel, expect, suPass);
        int allowedIPs = StringUtils.countOccurrencesOf(wg0AsString, "AllowedIPs");
        if (allowedIPs == 255) {
            throw new Exception("Not allowed more keys!");
        }
        goToWGFolder(expect);
        String peer = addNewPeer(getKeyByName(builder, expect, name, false), allowedIPs + 1 + "");
        String wg0WithAddedPeer = wg0AsString + "\n" + peer;
        ByteArrayInputStream stream = new ByteArrayInputStream(wg0WithAddedPeer.getBytes());

        downgradeToUser(expect, session.getUserName(), "poker");
        String uniqFolderName = getUniqFolderName();
        makeTmpDir(uniqFolderName, session.getUserName(), expect);

        sftpChannel.put(stream, "/home/" + session.getUserName() + "/" + uniqFolderName + "/wg0.conf");

        upgradeToSU(expect, suPass);

        moveFromTmpFolderToWGFolder(expect, session.getUserName(), uniqFolderName);

        removeTmpDir(uniqFolderName, session.getUserName(), expect);

        return true;
    }

    private static Expect getExpect(ChannelShell channel, StringBuilder builderIn, StringBuilder builderOut) throws IOException {
        return new ExpectBuilder()
                .withOutput(channel.getOutputStream())
                .withInputs(channel.getInputStream(), channel.getExtInputStream())
                .withEchoInput(builderIn)
                .withEchoOutput(builderOut)
                .withInputFilters(removeColors(), removeNonPrintable())
                .withExceptionOnFailure()
                .build();
    }

    @GetMapping("/getAllKeys")
    public Status getAllKeys(@RequestParam(name = "host") String host, @RequestParam(name = "supass") String supass ) {
        Status status = new Status();
        sessions.forEach((k, v) -> {
            ChannelShell channel;
            if (v.getHost().equals(host)) {
                try {
                    StringBuilder builderInput = new StringBuilder();
                    StringBuilder builder = new StringBuilder();
                    channel = (ChannelShell) v.openChannel("shell");
                    ChannelSftp sftpChannel = (ChannelSftp) v.openChannel("sftp");
                    sftpChannel.connect();
                    channel.connect();
                    Expect expect = new ExpectBuilder()
                            .withOutput(channel.getOutputStream())
                            .withInputs(channel.getInputStream(), channel.getExtInputStream())
                            .withEchoInput(builder)
                            .withEchoOutput(builderInput)
                            .withInputFilters(removeColors(), removeNonPrintable())
                            .withExceptionOnFailure()
                            .build();
                    try {

                        upgradeToSU(expect, supass);
                        goToWGFolder(expect);
                        builder.setLength(0);
                        expect.sendLine("ls");
                        Thread.sleep(500);
                        //todo:think
                        String trim = builder.toString().replaceAll("\r\n", " ").trim();
                        List<String> privatekey = Arrays.stream(trim.split(" ")).filter(i -> i.contains("privatekey")).collect(Collectors.toList());
                        status.setMessage(privatekey.toString());
                    } finally {
                        expect.close();
                        channel.disconnect();
                        sftpChannel.disconnect();
                    }
                } catch (Exception e) {
                    log.error("Error getAllKeys - {}", e.getMessage());
                }
            }
        });
        return status;
    }

    @GetMapping("/enablewgservice")
    public Status enablewgservice(@RequestParam(name = "host") String host) {
        Status status = new Status();
        sessions.forEach((k, v) -> {
            ChannelShell channel;
            if (v.getHost().equals(host)) {
                try {
                    StringBuilder builderInp = new StringBuilder();
                    StringBuilder builderOut = new StringBuilder();
                    channel = (ChannelShell) v.openChannel("shell");

                    channel.connect();
                    Expect expect = new ExpectBuilder()
                            .withTimeout(2, TimeUnit.SECONDS)
                            .withOutput(channel.getOutputStream())
                            .withInputs(channel.getInputStream(), channel.getExtInputStream())
                            .withEchoInput(builderInp)
                            .withEchoOutput(builderOut)
                            .withInputFilters(removeColors(), removeNonPrintable())
                            .withExceptionOnFailure()
                            .build();
                    try {
                        boolean enable = isEnable(expect);
                        if (!enable) {
                            enable(expect, v.getUserInfo().getPassword());
                        }
                        start(expect, v.getUserInfo().getPassword());
                    } finally {
                        expect.close();
                        channel.disconnect();
                    }
                } catch (Exception e) {
                    log.error("Enable service with exception {}, host {} ", e.getMessage(), v.getHost());
                }
            }
        });
        return status;
    }

    @GetMapping("/disablewgservice")
    public Status disablewgservice(@RequestParam(name = "host") String host, @RequestParam(name = "userPass") String userPass) {
        Status status = new Status();
        sessions.forEach((k, v) -> {
            ChannelShell channel;
            if (v.getHost().equals(host)) {
                try {
                    StringBuilder builderInp = new StringBuilder();
                    StringBuilder builderOut = new StringBuilder();
                    channel = (ChannelShell) v.openChannel("shell");

                    channel.connect();
                    Expect expect = new ExpectBuilder()
                            .withTimeout(2, TimeUnit.SECONDS)
                            .withOutput(channel.getOutputStream())
                            .withInputs(channel.getInputStream(), channel.getExtInputStream())
                            .withEchoInput(builderInp)
                            .withEchoOutput(builderOut)
                            .withInputFilters(removeColors(), removeNonPrintable())
                            .withExceptionOnFailure()
                            .build();
                    try {
                        stop(expect, userPass);
                        boolean enable = isEnable(expect);
                        if (enable) {
                            disable(expect, userPass);
                        }
                    } finally {
                        expect.close();
                        channel.disconnect();
                    }

                } catch (Exception e) {
                    log.error("Disable service with exception {}, host {} ", e.getMessage(), v.getHost());
                }

            }
        });
        return status;
    }
    public String getipinterface(String host) {
        List<String> result = new ArrayList<>();
        sessions.forEach((k, v) -> {
            ChannelShell channel;
            if (v.getHost().equals(host)) {
                try {
                    StringBuilder builderInp = new StringBuilder();
                    StringBuilder builderOut = new StringBuilder();
                    channel = (ChannelShell) v.openChannel("shell");

                    channel.connect();
                    Expect expect = new ExpectBuilder()
                            .withTimeout(2, TimeUnit.SECONDS)
                            .withOutput(channel.getOutputStream())
                            .withInputs(channel.getInputStream(), channel.getExtInputStream())
                            .withEchoInput(builderInp)
                            .withEchoOutput(builderOut)
                            .withInputFilters(removeColors(), removeNonPrintable())
                            .withExceptionOnFailure()
                            .build();
                    try {
                        builderInp.setLength(0);
                        getIPInterface(expect, host);
                        String outString = builderInp.toString();
                        String cutOne = outString.substring(outString.indexOf(host));
                        String cutTwo = cutOne.substring(cutOne.indexOf("\r\n"));
                        int indexTo = cutTwo.lastIndexOf("\r\n");
                        int indexSpaceBeforeTargetInterface = cutTwo.lastIndexOf(" ", indexTo);
                        result.add(cutTwo.substring(indexSpaceBeforeTargetInterface, indexTo).trim());
                    } finally {
                        expect.close();
                        channel.disconnect();
                    }

                } catch (Exception e) {
                    log.error("Disable service with exception {}, host {} ", e.getMessage(), v.getHost());
                }

            }
        });
        return result.size() > 0 ? result.get(0) : "";
    }

    private static boolean status(Expect expect, StringBuilder builder, String userPass) throws IOException {
        expect.sendLine("systemctl status wg-quick@wg0.service");
        waitComplete(expect,userPass);
        return builder.toString().contains("active (");
    }
    private static boolean restart(Expect expect, StringBuilder builder, String userPass) throws IOException {
        expect.sendLine("systemctl restart wg-quick@wg0.service");
        waitComplete(expect, userPass);
        return builder.toString().contains("active (");
    }

    private static void enable(Expect expect, String userPass) throws IOException {
        expect.sendLine("systemctl enable wg-quick@wg0.service");
        waitComplete(expect,userPass);
    }

    private static void disable(Expect expect, String userPass) throws IOException {
        expect.sendLine("systemctl disable wg-quick@wg0.service");
        waitComplete(expect,userPass);
    }

    private static boolean isEnable(Expect expect) throws IOException, InterruptedException {
        expect.sendLine("systemctl list-unit-files | grep wg-quick@");
        String input = expect.expect(contains("wg-quick@")).getInput();
        return !input.contains("disabled");
    }

    private static void waitComplete(Expect expect, String userPass) {
        int countwait = 1;
        try {
            while (true) {
                MultiResult result = expect.expect(
                        anyOf(
                                contains("Password:"),
                                contains("AUTHENTICATING FOR"),
                                contains("AUTHENTICATION COMPLETE"),
                                contains("AUTHENTICATION COMPLETE")
                        ));
                if (result.getInput().contains("Password:")) {
                    expect.sendLine(userPass);
                }
                if (result.getInput().contains("AUTHENTICATION COMPLETE")) {
                    if (countwait == 0) {
                        break;
                    }
                    countwait--;
                }
            }
        } catch (Exception e) {
        }
    }

    private static void start(Expect expect, String userPass) throws IOException {
        expect.sendLine("systemctl start wg-quick@wg0.service");
        waitComplete(expect, userPass);
    }

    private static void stop(Expect expect, String userPass) throws IOException {
        expect.sendLine("systemctl stop wg-quick@wg0.service");
        waitComplete(expect, userPass);
    }

    private String getWG0AsString(Session v, ChannelSftp sftpChannel, Expect expect, String suPass) throws Exception {
        boolean isTmpFolderCreated;
        String tmpFolder = getUniqFolderName();
        String result;
        isTmpFolderCreated = makeTmpDir(tmpFolder, v.getUserName(), expect);
        if (isTmpFolderCreated) {
            upgradeToSU(expect, suPass);
            result = moveFromWGFolderToOutputStream(expect, sftpChannel, v.getUserName(), tmpFolder).toString();
            removeTmpDir(tmpFolder, v.getUserName(), expect);
        } else {
            throw new Exception("TmpFolder not created!");
        }
        return result;
    }

    @GetMapping("/powerOff")
    public String powerOff(@RequestParam(name = "host") String host, @RequestParam(name = "suPass") String suPass) throws Exception {
        try {
            sessions.forEach((k, v) -> {
                if (v.getHost().equals(host)) {
                    ChannelExec channel = null;
                    try {
                        channel = (ChannelExec) v.openChannel("exec");

                        ByteArrayOutputStream responseStream = new ByteArrayOutputStream();
                        channel.setOutputStream(responseStream);

                        channel.setCommand(String.format("echo %s | sudo -S poweroff", suPass));

                        channel.connect();

                        while (channel.isConnected()) {
                            Thread.sleep(3000);
                        }


                    } catch (JSchException | InterruptedException e) {
                        throw new RuntimeException(e);
                    } finally {
                        if (channel != null) {
                            channel.disconnect();
                        }
                    }
                }
            });

            return "Power off" + host;
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        throw new Exception("Not power off by host " + host);
    }

    private static void moveFromTmpFolderToWGFolder(Expect expect, String userName, String tmpFolder) {
        try {
            expect.sendLine("cp " + "/home/" + userName + "/" + tmpFolder + "/wg0.conf" + " /etc/wireguard/wg0.conf");
            Thread.sleep(100);
        } catch (Exception e) {
            log.error("Not moved file to wg folder");
        }
    }

    private static void goToWGFolder(Expect expect) {
        try {
            expect.sendLine("cd " + "/etc/wireguard/");
            Thread.sleep(100);
        } catch (Exception e) {
            log.error("Not go to wg folder");
        }
    }

    private static ByteArrayOutputStream moveFromWGFolderToOutputStream(Expect expect, ChannelSftp sftp, String userName, String tmpFolder) throws Exception {
        try {
            expect.sendLine("cp" + " /etc/wireguard/wg0.conf" + " /home/" + userName + "/" + tmpFolder + "/wg0.conf");
            Thread.sleep(100);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            sftp.get("/home/" + userName + "/" + tmpFolder + "/wg0.conf", byteArrayOutputStream);
            Thread.sleep(100);
            return byteArrayOutputStream;
        } catch (Exception e) {
            log.error("Not moved file to wg folder");
            throw new Exception("Not receive outpustream with file");
        }
    }
    private static void getIPInterface(Expect expect, String host) throws Exception {
            expect.sendLine("ip a | grep \"" + host + "\""
              );
            Thread.sleep(1000);
    }

    private static ByteArrayInputStream prepareRawWG0ConfFile(String privatekey, String ip, String mainInterface) {
        String defaultIp = "10.0.0.1/24";
        String toWrite = """
                [Interface]
                PrivateKey = %s
                Address = %s
                """;
        String end = """
                ListenPort = 51830
                PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
                PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE""";
        if(!mainInterface.isBlank()){
            end = end.replaceAll("eth0", mainInterface);
        }

        String outString = String.format(toWrite, privatekey, ip.isBlank() ? defaultIp : ip) + end;
        return new ByteArrayInputStream(outString.getBytes(StandardCharsets.UTF_8));
    }
    private static String makeClientWGConf(String privatekey, String address, String publickey, String endpoint) {
        String toWrite = """
                              [Interface]
                              PrivateKey = %s
                              Address = %s
                              DNS = 1.1.1.1
                              
                              [Peer]
                              PublicKey = %s
                              AllowedIPs = 0.0.0.0/0
                              Endpoint = %
                              PersistentKeepalive = 20
                """;

        return String.format(toWrite, privatekey, address, publickey, endpoint);
    }

    /**
     * @param publicKey - key
     * @param ip        ,sample 10.0.0.1/24
     */
    private static String addNewPeer(String publicKey, String ip) {
        String peer = """
                [Peer]
                PublicKey = %s
                AllowedIPs = 10.0.0.%s
                """;
        return String.format(peer, publicKey, ip);
    }

    private static String getKeyByName(StringBuilder builder, Expect expect, String name, boolean isPrivateKey) throws Exception {
        String finishNameKey = isPrivateKey ? name + "_privatekey" : name + "_publickey";
        builder.setLength(0);
        Thread.sleep(100);
        expect.sendLine("ls");
        Thread.sleep(100);
        String trim = builder.toString().replaceAll("\r\n", " ").trim();
        List<String> privatekey = Arrays.stream(trim.split(" ")).filter(i -> i.contains(finishNameKey)).toList();
        if (privatekey.size() == 0) {
            throw new Exception("private key not found!");
        }
        builder.setLength(0);
        Thread.sleep(100);
        expect.sendLine("cat " + finishNameKey);
        Thread.sleep(100);
        String result;
        if (!builder.toString().isBlank()) {
            result = builder.toString().split("\r\n")[1].trim();
        } else {
            throw new Exception("private key exist but not find from output!");
        }
        return result;
    }


    private static String getUniqFolderName() {
        return UUID.randomUUID().toString();
    }

    private void upgradeToSU(Expect expect, String password) {
        try {
            expect.sendLine("sudo su");
            Thread.sleep(100);
            expect.sendLine(password);
            Thread.sleep(100);
        } catch (Exception e) {
            log.error("No upgrade to SU not created , reason ->" + e.getMessage());
        }

    }

    private void downgradeToUser(Expect expect, String user, String password) {
        try {
            expect.sendLine("sudo su " + user);
            Thread.sleep(100);
            expect.sendLine(password);
            Thread.sleep(100);
        } catch (Exception e) {
            log.error("No downgrade to User not created , reason ->" + e.getMessage());
        }

    }

    private boolean makeTmpDir(String nameDir, String userName, Expect expect) {
        try {
            expect.sendLine("mkdir /home/" + userName + "/" + nameDir);
            Thread.sleep(100);
            return true;
        } catch (Exception e) {
            log.error("Folder with name " + nameDir + " not created , reason ->" + e.getMessage());
            return false;
        }
    }

    private void removeTmpDir(String nameDir, String userName, Expect expect) {
        try {
            expect.sendLine("rm -rf /home/" + userName + "/" + nameDir);
            Thread.sleep(100);
        } catch (Exception e) {
            log.error("Folder with name " + nameDir + " not deleted , reason ->" + e.getMessage());
        }
    }

    private void enableIPForwarding(Expect expect, StringBuilder builder) {
        try {
            expect.sendLine("echo \"net.ipv4.ip_forward=1\" >> /etc/sysctl.conf");
            Thread.sleep(100);
            builder.setLength(0);
            expect.sendLine("sysctl -p");
            Thread.sleep(100);
            if (builder.toString().contains("net.ipv4.ip_forward = 1")) {
            }
        } catch (Exception e) {
            log.error("IPForwardind not set" + e.getMessage());
        }
    }

}
