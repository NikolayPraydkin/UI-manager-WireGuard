package ru.priadkin.uimanegerwireguard.sshconnect.domain;

import lombok.Data;

@Data
public class Status {
    private String message;
    private boolean isInstaledWireguard;
}
