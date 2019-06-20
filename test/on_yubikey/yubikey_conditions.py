from ykman.util import is_cve201715361_vulnerable_firmware_version


def yubikey_condition(condition):
    def decorate(method):
        method_conditions = (
            getattr(method, '_yubikey_conditions')
            if '_yubikey_conditions' in dir(method)
            else set())
        method_conditions.add(condition)
        setattr(method, '_yubikey_conditions', method_conditions)
        return method
    return decorate


@yubikey_condition
def is_fips(dev):
    return dev.is_fips


@yubikey_condition
def is_not_fips(dev):
    return not dev.is_fips


@yubikey_condition
def is_neo(dev):
    return dev.version < (4, 0, 0)


@yubikey_condition
def is_not_neo(dev):
    return dev.version >= (4, 0, 0)


@yubikey_condition
def supports_piv_attestation(dev):
    return dev.version >= (4, 3, 0)


@yubikey_condition
def not_supports_piv_attestation(dev):
    return dev.version < (4, 3, 0)


@yubikey_condition
def is_roca(dev):
    return is_cve201715361_vulnerable_firmware_version(dev.version)


@yubikey_condition
def is_not_roca(dev):
    return not is_cve201715361_vulnerable_firmware_version(dev.version)


def version_min(min_version):
    return yubikey_condition(lambda dev: dev.version >= min_version)