#!/bin/sh
# vim:syntax=scheme expandtab
exec junkie -c $0
!#

(define-module (junkie synbl))
(export ('blacklist 'synbl-ban 'synbl-unban))
(use-modules (srfi srfi-69))
(use-modules (guile-user))

(use-syntax (ice-9 syncase))
(define-syntax assert
  (syntax-rules ()
                ((assert x)
                 (if (not x) (throw 'Assertion-failed 'x)))))

(set-log-file "/dev/stdout")
(load-plugin "../src/.libs/synbl.so")
(set-log-level 7 "synbl")

; blacklist if more than 2 syns per sec
(set-max-syn 2)
(set-period 1)
(set-probation 4)
(set-quit-when-done #f)

(define blacklist (make-hash-table))

(define (synbl-ban ip dport)
  (let ((k (cons ip dport)))
    (simple-format #t "Banning ~a\n" ip)
    (hash-table-set! blacklist k k)))

(define (synbl-unban ip dport)
  (let ((k (cons ip dport)))
    (simple-format #t "Unbanning ~a\n" ip)
    (hash-table-delete! blacklist k)))

; Replay a pcap with some syns at full speed
(open-pcap "pcap/syns.pcap")

(sleep 1)
(assert (equal? 1 (hash-table-size blacklist)))
(assert (hash-table-exists? blacklist (cons "192.168.10.9" 22)))
; wait more for probation period
(sleep 4)
(assert (equal? 0 (hash-table-size blacklist)))

(exit)
