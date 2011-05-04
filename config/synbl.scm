; vim:syntax=scheme expandtab
;;; This file defines the two guile functions called by the plugin,
;;; one to blacklist an IP and the other one the reenable it.
(define-module (junkie synbl))
(use-modules (guile-user))
(if (not (load-plugin "synbl.so"))
    (begin (display "Cannot load synbl.so plugin\n")
           (exit 1)))

(define (do-iptables cmd ip dport)
  (system (simple-format #f "iptables ~a INPUT -s ~a/32 -p tcp --syn --dport ~a -d 0/0 -j DROP" cmd ip dport)))

(define-public (synbl-ban ip dport)
  (simple-format #t "Banning IP ~a, dport ~a~%" ip dport)
  (do-iptables "-A" ip dport))

(define-public (synbl-unban ip dport)
  (simple-format #t "Unbanning IP ~a, dport ~a~%" ip dport)
  (do-iptables "-D" ip dport))
