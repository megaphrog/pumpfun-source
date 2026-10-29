#!/usr/bin/env python3
"""Offline malformed-input smoke tests; not a functional or authorization audit."""
import hashlib,json,pathlib,random
from solders.litesvm import LiteSVM
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.instruction import Instruction
from solders.transaction import Transaction
from solders.transaction_metadata import FailedTransactionMetadata
from analyze import program_addresses
ROOT=pathlib.Path(__file__).resolve().parents[1]
def main():
    results={}; payer=Keypair.from_seed(bytes(range(32))); rng=random.Random(10424)
    for name,address in program_addresses().items():
        svm=LiteSVM().with_transaction_history(0); svm.airdrop(payer.pubkey(),10**10)
        program=Pubkey.from_string(address); svm.add_program_from_file(program,ROOT/f'evidence/original/{name}/deployed.so')
        tests=[('empty',b''),('short',b'\x01'*7),('unknown',b'\xff'*8)]
        idl=ROOT/f'evidence/upstream/{name}.json'
        if idl.exists():
            for ix in json.loads(idl.read_text())['instructions']: tests.append((ix['name']+'-missing-accounts',bytes(ix['discriminator'])))
        for i in range(64): tests.append((f'random-{i}',rng.randbytes(8+i)))
        rows=[]
        for label,data in tests:
            tx=Transaction.new_signed_with_payer([Instruction(program,data,[])],payer.pubkey(),[payer],svm.latest_blockhash())
            result=svm.send_transaction(tx); failed=isinstance(result,FailedTransactionMetadata)
            rows.append({'case':label,'input_hex':data.hex(),'rejected':failed,'error':str(result.err()) if failed else None,'logs':result.meta().logs() if failed else result.logs()})
        results[name]={'binary_sha256':hashlib.sha256((ROOT/f'evidence/original/{name}/deployed.so').read_bytes()).hexdigest(),'cases':rows,'all_rejected':all(x['rejected'] for x in rows)}
        print(name,len(rows),results[name]['all_rejected'],flush=True)
    (ROOT/'audit/local-validation.json').write_text(json.dumps({'runtime':'solders 0.27.1 / LiteSVM','scope':'Malformed instruction data and missing accounts only; no network or broadcast. No valid-state authorization/economic/CPI coverage.','programs':results},indent=2)+'\n')
    assert all(x['all_rejected'] for x in results.values())
if __name__=='__main__': main()
