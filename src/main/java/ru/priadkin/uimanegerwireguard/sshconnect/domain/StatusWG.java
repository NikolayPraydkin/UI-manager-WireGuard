package ru.priadkin.uimanegerwireguard.sshconnect.domain;

import lombok.Data;

@Data
public class StatusWG extends Status{
    private boolean isInstaledWireguard;
}
