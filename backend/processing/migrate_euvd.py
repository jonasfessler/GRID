import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import UpdateOne

async def migrate_euvd():
    client = AsyncIOMotorClient("mongodb://localhost:27017/")
    db = client["GRIDr"]
    coll = db["euvd"]

    print("Starting migration of EUVD documents...")
    cursor = coll.find({}, {"id": 1, "aliases": 1})
    ops = []
    count = 0

    async for doc in cursor:
        aliases = doc.get("aliases", "")
        # Extract CVE IDs (same logic as ingest)
        cve_ids = [t.strip() for t in aliases.split() if t.strip().startswith("CVE-")]
        
        ops.append(UpdateOne({"_id": doc["_id"]}, {"$set": {"_cve_ids": cve_ids}}))
        
        if len(ops) >= 1000:
            await coll.bulk_write(ops)
            ops = []
            count += 1000
            print(f"Processed {count} entries...")

    if ops:
        await coll.bulk_write(ops)
    
    print("Creating index...")
    await coll.create_index("_cve_ids")
    print("Migration complete.")

if __name__ == "__main__":
    asyncio.run(migrate_euvd())