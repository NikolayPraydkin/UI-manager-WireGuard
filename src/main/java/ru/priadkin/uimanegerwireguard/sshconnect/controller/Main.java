package ru.priadkin.uimanegerwireguard.sshconnect.controller;

import ch.qos.logback.classic.net.server.HardenedLoggingEventInputStream;
import ch.qos.logback.core.read.ListAppender;
import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.ChannelShell;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import lombok.extern.slf4j.Slf4j;
import net.sf.expectit.Expect;
import net.sf.expectit.ExpectBuilder;
import org.apache.commons.io.output.StringBuilderWriter;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import ru.priadkin.uimanegerwireguard.sshconnect.domain.SSH;
import ru.priadkin.uimanegerwireguard.sshconnect.domain.Status;
import ru.priadkin.uimanegerwireguard.sshconnect.domain.StatusWG;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static net.sf.expectit.filter.Filters.removeColors;
import static net.sf.expectit.filter.Filters.removeNonPrintable;
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
            ChannelExec channel;
            if (v.getHost().equals(host)) {
                try {
                    channel = (ChannelExec) v.openChannel("exec");
                    channel.setCommand("dpkg -s wireguard");
                    InputStream in = channel.getInputStream();

                    channel.connect();

                    byte[] tmp = new byte[1024];
                    StringBuilder builder = new StringBuilder();
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
                        try {
                            Thread.sleep(1000);
                        } catch (Exception ee) {
                        }
                    }
                    String statusWG = builder.toString();
                    if (statusWG.contains("Status: install ok")) {
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

    @GetMapping("/installwireguard")
    public StatusWG installwg(@RequestParam(name = "host") String host) {
        StatusWG status = new StatusWG();
        sessions.forEach((k, v) -> {
            ChannelExec channel = null;
            if (v.getHost().equals(host)) {
                try {
                    channel = (ChannelExec) v.openChannel("exec");
                    channel.setCommand("echo poker | sudo -S apt install -y wireguard");
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

    @GetMapping("/removewireguard")
    public StatusWG removewg(@RequestParam(name = "host") String host) {
        StatusWG status = new StatusWG();
        sessions.forEach((k, v) -> {
            ChannelExec channel = null;
            if (v.getHost().equals(host)) {
                try {
                    channel = (ChannelExec) v.openChannel("exec");
                    channel.setCommand("echo poker | sudo -S apt --purge remove -y wireguard; echo poker | sudo apt autoclean && sudo apt autoremove -y");

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

    @GetMapping("/generatekeyswg")
    public Status generateKeysWG(@RequestParam(name = "host") String host, @RequestParam(name = "keyname", required = false) String keyname, @RequestParam(name = "overridekey", required = false) boolean overridekey) {
        String prefixNameKeys = "";
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
                                    .build();
                    ) {

                        expect.sendLine("sudo su");
                        Thread.sleep(100);
                        expect.expect(regexp(".*"));
                        expect.sendLine("poker");
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

                    channel.disconnect();

                } catch (JSchException e) {
                    throw new RuntimeException(e);
                } catch (Exception e) {
                    status.setMessage(e.getMessage());
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
            , @RequestParam(name = "overwriteexistingconf", defaultValue = "false") boolean overwrite
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
                    Expect expect = new ExpectBuilder()
                            .withOutput(channel.getOutputStream())
                            .withInputs(channel.getInputStream(), channel.getExtInputStream())
                            .withEchoInput(builderIn)
                            .withEchoOutput(builderOut)
                            .withInputFilters(removeColors(), removeNonPrintable())
                            .withExceptionOnFailure()
                            .build();
                    boolean isTmpFolderCreated = false;
                    try {
                        String tmpFolder = getUniqFolderName();
                        //check exist wg0.conf
                        boolean exists = false;
                        try {
                            isTmpFolderCreated = makeTmpDir(tmpFolder, v.getUserName(), expect);
                            upgradeToSU(expect, "poker");
                            goToWGFolder(expect);
                            moveFromWGFolderToOutputStream(expect, sftpChannel, v.getUserName(), tmpFolder);
                            exists = true;
                        } catch (Exception e) {
                        }
                        removeTmpDir(tmpFolder, v.getUserName(), expect);
                        if (!exists || overwrite) {
                            Path path = prepareRawWG0ConfFile(getKeyByName(builderIn, expect, namekey.isBlank() ? "wg" : namekey, true), ip.isBlank() ? "" : ip);
                            downgradeToUser(expect, v.getUserName(), "poker");
                            isTmpFolderCreated = makeTmpDir(tmpFolder, v.getUserName(), expect);
                            if (isTmpFolderCreated) {
                                sftpChannel.put(path.toAbsolutePath().toString(), "/home/" + v.getUserName() + "/" + tmpFolder + "/wg0.conf");

                                upgradeToSU(expect, "poker");

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
                        expect.close();
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
    public Status getwg0conf(@RequestParam(name = "host") String host) {
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
                        String wg0AsString = getWG0AsString(v, sftpChannel, expect);
                        status.setMessage(wg0AsString);
                    } finally {
                        expect.close();
                        channel.disconnect();
                    }
                } catch (Exception e) {
                    System.out.println(e.getMessage());
                }
            }
        });
        return status;
    }

    @GetMapping("/addPeerToWg0")
    public Status addpeertowg0(@RequestParam(name = "host") String host, @RequestParam(name = "name") String name) {
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
                        addPeerToWg0Conf(v,expect,channel,sftpChannel, builderIn, name);
                    } finally {
                        expect.close();
                        channel.disconnect();
                    }
                } catch (Exception e) {
                    System.out.println(e.getMessage());
                }
            }
        });
        return status;
    }

    private boolean addPeerToWg0Conf(Session session, Expect expect, ChannelShell channel, ChannelSftp sftpChannel,StringBuilder builder, String name) throws Exception {
        String wg0AsString = getWG0AsString(session, sftpChannel, expect);
        int allowedIPs = StringUtils.countOccurrencesOf(wg0AsString, "AllowedIPs");
        if (allowedIPs == 255) {
            throw new Exception("Not allowed more keys!");
        }
        goToWGFolder(expect);
        String peer = addNewPeer(getKeyByName(builder, expect, name, false), allowedIPs + 1 + "");
        String wg0WithAddedPeer = wg0AsString + "\n" +peer;
        ByteArrayInputStream stream = new ByteArrayInputStream(wg0WithAddedPeer.getBytes());

        downgradeToUser(expect, session.getUserName(), "poker");
        String uniqFolderName = getUniqFolderName();
        makeTmpDir(uniqFolderName, session.getUserName(), expect);

            sftpChannel.put(stream, "/home/" + session.getUserName() + "/" + uniqFolderName + "/wg0.conf");

            upgradeToSU(expect, "poker");

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
    public Status getAllKeys(@RequestParam(name = "host") String host) {
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

                        upgradeToSU(expect, "poker");
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
                    }
                } catch (Exception e) {
                    System.out.println(e.getMessage());
                }
            }
        });
        return status;
    }

    private List<String> splitWG0(String conf) {
        return Stream.of(conf.split("\n")).collect(Collectors.toList());
    }

    private String getWG0AsString(Session v, ChannelSftp sftpChannel, Expect expect) throws Exception {
        boolean isTmpFolderCreated;
        String tmpFolder = getUniqFolderName();
        String result;
        isTmpFolderCreated = makeTmpDir(tmpFolder, v.getUserName(), expect);
        if (isTmpFolderCreated) {
            upgradeToSU(expect, "poker");
            result = moveFromWGFolderToOutputStream(expect, sftpChannel, v.getUserName(), tmpFolder).toString();
            removeTmpDir(tmpFolder, v.getUserName(), expect);
        } else {
            throw new Exception("TmpFolder not created!");
        }
        return result;
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

    private static boolean moveFromTmpFolderToWGFolder(Expect expect, String userName, String tmpFolder) throws IOException {
        try {
            expect.sendLine("cp " + "/home/" + userName + "/" + tmpFolder + "/wg0.conf" + " /etc/wireguard/wg0.conf");
            Thread.sleep(100);
            return true;
        } catch (Exception e) {
            log.error("Not moved file to wg folder");
            return false;
        }
    }

    private static boolean goToWGFolder(Expect expect) throws IOException {
        try {
            expect.sendLine("cd " + "/etc/wireguard/");
            Thread.sleep(100);
            return true;
        } catch (Exception e) {
            log.error("Not go to wg folder");
            return false;
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

    private static Path prepareRawWG0ConfFile(String privatekey, String ip) throws IOException {
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

        String outString = String.format(toWrite, privatekey, ip.isBlank() ? defaultIp : ip) + end;
        Path path = Paths.get("wg0.conf");
        Files.write(path, outString.getBytes());
        return path;
    }

    /**
     * @param publicKey - key
     * @param ip        ,sample 10.0.0.1/24
     * @return
     * @throws IOException
     */
    private static String addNewPeer(String publicKey, String ip) throws IOException {
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
        List<String> privatekey = Arrays.stream(trim.split(" ")).filter(i -> i.contains(finishNameKey)).collect(Collectors.toList());
        if (privatekey.size() == 0) {
            throw new Exception("private key not found!");
        }
        builder.setLength(0);
        Thread.sleep(100);
        expect.sendLine("cat " + finishNameKey);
        Thread.sleep(100);
        String result = "";
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

    private boolean upgradeToSU(Expect expect, String password) {
        try {
            expect.sendLine("sudo su");
            Thread.sleep(100);
            expect.sendLine(password);
            Thread.sleep(100);
            return true;
        } catch (Exception e) {
            log.error("No upgrade to SU not created , reason ->" + e.getMessage());
            return false;
        }

    }

    private boolean downgradeToUser(Expect expect, String user, String password) {
        try {
            expect.sendLine("sudo su " + user);
            Thread.sleep(100);
            expect.sendLine(password);
            Thread.sleep(100);
            return true;
        } catch (Exception e) {
            log.error("No downgrade to User not created , reason ->" + e.getMessage());
            return false;
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

    private boolean removeTmpDir(String nameDir, String userName, Expect expect) {
        try {
            expect.sendLine("rm -rf /home/" + userName + "/" + nameDir);
            Thread.sleep(100);
            return true;
        } catch (Exception e) {
            log.error("Folder with name " + nameDir + " not deleted , reason ->" + e.getMessage());
            return false;
        }
    }

}
