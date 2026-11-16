------------------------------ MODULE ReferenceMonitor ------------------------------
(***************************************************************************)
(* Формальная модель политики безопасности монитора обращений Pinnacle    *)
(* (backend/src/security/accessControl.ts).                                *)
(*                                                                         *)
(* Моделируется:                                                           *)
(*   - мандатное правило чтения: допуск субъекта >= метки объекта          *)
(*     (Bell-LaPadula, simple security property, «нет чтения вверх»);     *)
(*   - аутентификация администратора и блокировка источника после          *)
(*     MaxFailures неудачных попыток;                                       *)
(*   - регистрация каждой неудачной попытки и каждого отказа в журнале.    *)
(*                                                                         *)
(* Проверка: java -cp tla2tools.jar tlc2.TLC -config ReferenceMonitor.cfg  *)
(*           ReferenceMonitor.tla                                          *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS IPs, MaxFailures

Levels      == 0..3                     \* public, internal, confidential, secret
Anonymous   == 0                        \* допуск анонимного субъекта
AdminLevel  == 2                        \* допуск администратора (confidential)
Outcomes    == {"none", "granted", "denied", "unauthorized", "locked"}

VARIABLES
    failures,      \* число неудачных попыток по каждому IP
    locked,        \* заблокирован ли IP
    last,          \* последнее решение монитора
    auditFailures, \* записей auth.failure в журнале
    realFailures,  \* фактических неудачных попыток (для сверки с журналом)
    auditDenied,   \* записей access.denied в журнале
    realDenied     \* фактических отказов по мандатному правилу

vars == <<failures, locked, last, auditFailures, realFailures, auditDenied, realDenied>>

Decision == [ outcome   : Outcomes,
              clearance : Levels,
              level     : Levels,
              wasLocked : BOOLEAN ]

TypeOK ==
    /\ failures \in [IPs -> 0..MaxFailures]
    /\ locked   \in [IPs -> BOOLEAN]
    /\ last     \in Decision
    /\ auditFailures \in Nat /\ realFailures \in Nat
    /\ auditDenied   \in Nat /\ realDenied   \in Nat

Init ==
    /\ failures = [ip \in IPs |-> 0]
    /\ locked   = [ip \in IPs |-> FALSE]
    /\ last     = [outcome |-> "none", clearance |-> 0, level |-> 0, wasLocked |-> FALSE]
    /\ auditFailures = 0 /\ realFailures = 0
    /\ auditDenied = 0   /\ realDenied = 0

(* Решение о доступе после идентификации субъекта: правило canRead(). *)
Mediate(ip, clearance, lvl) ==
    IF clearance >= lvl
    THEN /\ last' = [outcome |-> "granted", clearance |-> clearance,
                     level |-> lvl, wasLocked |-> locked[ip]]
         /\ UNCHANGED <<auditDenied, realDenied>>
    ELSE /\ last' = [outcome |-> "denied", clearance |-> clearance,
                     level |-> lvl, wasLocked |-> locked[ip]]
         /\ auditDenied' = auditDenied + 1
         /\ realDenied'  = realDenied + 1

(* Запрос без заголовка Authorization — анонимный субъект. *)
AnonymousRequest(ip, lvl) ==
    /\ Mediate(ip, Anonymous, lvl)
    /\ UNCHANGED <<failures, locked, auditFailures, realFailures>>

(* Запрос с токеном. tokenOk — совпал ли bcrypt-хеш. *)
AuthRequest(ip, tokenOk, lvl) ==
    IF locked[ip]
    THEN /\ last' = [outcome |-> "locked", clearance |-> 0, level |-> lvl, wasLocked |-> TRUE]
         /\ UNCHANGED <<failures, locked, auditFailures, realFailures, auditDenied, realDenied>>
    ELSE IF tokenOk
    THEN /\ failures' = [failures EXCEPT ![ip] = 0]
         /\ Mediate(ip, AdminLevel, lvl)
         /\ UNCHANGED <<locked, auditFailures, realFailures>>
    ELSE /\ failures' = [failures EXCEPT ![ip] = failures[ip] + 1]
         /\ locked'   = [locked   EXCEPT ![ip] = (failures[ip] + 1 >= MaxFailures)]
         /\ last' = [outcome |-> "unauthorized", clearance |-> 0, level |-> lvl, wasLocked |-> FALSE]
         /\ auditFailures' = auditFailures + 1
         /\ realFailures'  = realFailures + 1
         /\ UNCHANGED <<auditDenied, realDenied>>

(* Истечение времени блокировки (LOCKOUT_MS). *)
Unlock(ip) ==
    /\ locked[ip]
    /\ locked'   = [locked   EXCEPT ![ip] = FALSE]
    /\ failures' = [failures EXCEPT ![ip] = 0]
    /\ UNCHANGED <<last, auditFailures, realFailures, auditDenied, realDenied>>

Next ==
    \E ip \in IPs, lvl \in Levels :
        \/ AnonymousRequest(ip, lvl)
        \/ \E ok \in BOOLEAN : AuthRequest(ip, ok, lvl)
        \/ Unlock(ip)

Spec == Init /\ [][Next]_vars

\* Ограничение пространства состояний для TLC (счётчики журнала растут неограниченно).
StateBound == auditFailures <= 8 /\ auditDenied <= 8

(*************************** Свойства безопасности ***************************)

\* 1. Нет чтения вверх: доступ предоставлен только при допуске >= метки.
NoReadUp == last.outcome = "granted" => last.clearance >= last.level

\* 2. Аноним никогда не получает объекты с меткой выше public.
AnonymousOnlyPublic ==
    (last.outcome = "granted" /\ last.clearance = Anonymous) => last.level = 0

\* 3. Заблокированный источник не получает доступ даже с верным токеном.
NoGrantWhileLocked == last.outcome = "granted" /\ last.clearance > 0 => ~last.wasLocked

\* 4. Ни один объект с меткой secret недоступен никому через API.
SecretNeverReadable == last.outcome = "granted" => last.level < 3

\* 5. Полнота аудита: каждая неудачная попытка и каждый отказ записаны.
AuditComplete == auditFailures = realFailures /\ auditDenied = realDenied

\* 6. Счётчик попыток не превышает порога блокировки.
LockoutBound == \A ip \in IPs : failures[ip] <= MaxFailures

==================================================================================
