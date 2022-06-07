class IrcGroupAttack:
    def __init__(self, botNicks, startSendedTime, stopSendedTime, attackDuration, 
            startAttackSettings, stopAttackSettings):
        self.botNicks = botNicks
        self.startSendedTime = startSendedTime
        self.stopSendedTime = stopSendedTime
        self.attackDuration = attackDuration
        self.startAttackSettings = startAttackSettings
        self.stopAttackSettings = stopAttackSettings
        