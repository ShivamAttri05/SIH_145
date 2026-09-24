from scapy.all import get_if_list


print("=" * 70)
print("AVAILABLE NETWORK INTERFACES")
print("=" * 70)

interfaces = get_if_list()

for index, interface in enumerate(interfaces, start=1):
    print(f"{index}. {interface}")

print()
print("=" * 70)
print(f"TOTAL INTERFACES: {len(interfaces)}")
print("=" * 70)