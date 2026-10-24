package localauth

// Verifications returns how many Argon2id verifications ran (tests).
func (svc *Service) Verifications() int64 { return svc.h.calls.Load() }
