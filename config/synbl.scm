; vim:syntax=scheme expandtab
;;; This file will define the two guile function called by the plugin,
;;; one to blacklist an IP and the other one the reenable it.
(define-module (junkie synbl))

(define (synbl-ban ip dport)
  (simple-format #t "Banning IP ~a, dport ~a\n" ip dport))

