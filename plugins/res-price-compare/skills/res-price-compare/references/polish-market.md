# Polish E-commerce Market — Knowledge Base

This file is **ALWAYS** loaded alongside SKILL.md. It contains shop lists, price comparators,
and search patterns for price comparison on the Polish market.

## Price Comparators

Always start searching from price comparators — they provide lists of many shops at once.

| Comparator | URL | Notes |
|-----------|-----|-------|
| Ceneo.pl | ceneo.pl | Largest in PL, best coverage, start here |
| Skapiec.pl | skapiec.pl | Smaller, but sometimes cheaper |
| Geizhals.eu | geizhals.eu | European, good for electronics |

### Search Patterns

```
site:ceneo.pl "{PRODUCT}"
"{PRODUCT}" ceneo porównanie cen
```

**Tip:** WebFetch of a Ceneo product page returns a list of shops with prices, shipping, and availability.

## Marketplaces

| Marketplace | URL | Notes |
|------------|-----|-------|
| Allegro.pl | allegro.pl | Largest in PL, many sellers, watch warranty type |
| Amazon.pl | amazon.pl | Marketplace — verify seller and product origin |
| OLX.pl | olx.pl | Used and new, no warranty on private listings |

### Search Patterns

```
site:allegro.pl "{PRODUCT}"
"{PRODUCT}" allegro
site:amazon.pl "{PRODUCT}"
```

**Note Allegro:** WebFetch returns 403. Use WebSearch with `site:allegro.pl`.
**Note Amazon:** WebFetch returns CAPTCHA. Use WebSearch with `site:amazon.pl`.

## Large Electronics Shops

General shops with wide assortment. Always check these.

| Shop | URL | Free Shipping | Notes |
|------|-----|--------------|-------|
| x-kom.pl | x-kom.pl | Yes (often) | Large, but reseller warranty (not manufacturer!) |
| Morele.net | morele.net | From 399 PLN | Manufacturer warranty, large assortment |
| Komputronik.pl | komputronik.pl | None | Large, verify warranty type |
| Media Expert | mediaexpert.pl | From 299 PLN | Mainly appliances/electronics |
| RTV Euro AGD | euro.com.pl | From 250 PLN | Mainly appliances/electronics, sister sites: oleole.pl, electro.pl |
| MediaMarkt.pl | mediamarkt.pl | Yes (free) | Large appliances/electronics, installments, free delivery |
| Rozetka.pl | rozetka.pl | From 199 PLN | Ukrainian chain, present in PL |

### Search Patterns

```
site:x-kom.pl "{PRODUCT}"
site:morele.net "{PRODUCT}"
site:komputronik.pl "{PRODUCT}"
site:mediamarkt.pl "{PRODUCT}"
```

### WebFetch — Known Limitations

| Shop | Problem | Workaround |
|------|---------|------------|
| x-kom.pl | 403 Forbidden | WebSearch `site:x-kom.pl` |
| Komputronik.pl | Dynamic rendering, no prices in HTML | WebSearch `site:komputronik.pl` |
| Electro.pl | 403 Forbidden | WebSearch `site:electro.pl` |
| Cyfrowe.pl | 403 Forbidden | WebSearch `site:cyfrowe.pl` |

## Specialist Shops by Category

### Apple / Authorized Resellers

Shops from Apple's official distribution channel in Poland. Manufacturer warranty guaranteed.

| Shop | URL | Status | Notes |
|------|-----|--------|-------|
| Cortland.pl | cortland.pl | Apple Premium Reseller | WebFetch 403, long lead time (3-5 weeks) |
| iSpot.pl | ispot.pl | Apple Premium Partner | Brick-and-mortar + online |
| iDream.pl | idream.pl | Apple Premium Reseller | WebFetch 403, prices at MSRP level |
| Lantre.pl | lantre.pl | Authorized Reseller | Official PL distribution, manufacturer warranty confirmed, competitive prices |
| iMad.pl | imad.pl | Authorized Reseller | WebFetch requires JS, dynamic rendering |

**Tip:** Apple authorized resellers have prices close to MSRP. For cheaper offers, search Ceneo for smaller resellers.

### Computers / Smaller IT Shops

Smaller computer shops from Ceneo — often cheapest prices, but verify warranty type.

| Shop | URL | Notes |
|------|-----|-------|
| artbi.eu | artbi.eu | Kraków, Ceneo 4.95/5, Trusted Reviews cert, since 2013 |
| delkom.pl | delkom.pl | Since 2000, good reviews, fast shipping |
| itnes.pl | itnes.pl | **B2B ONLY**, Poznań, HP partner, no 14-day returns |
| krsystem.pl | krsystem.pl | Computer shop, competitive prices |
| servecom.pl | servecom.pl | Computers, servers |
| SuperTech.pl | supertech.pl | Computer shop |

### VoIP / IP Telephony

| Shop | URL | Notes |
|------|-----|-------|
| 4ip.pl | 4ip.pl | Kontel (Yealink importer), cheap, manufacturer warranty |
| voip24sklep.pl | voip24sklep.pl | Specialist VoIP shop |
| sklep.telepol.pl | sklep.telepol.pl | Business telephony |
| kontel.net | kontel.net | Yealink distributor PL (B2B) |
| supervoip.pl | supervoip.pl | VoIP and SIP services |
| aksonet.pl | aksonet.pl | Networking and VoIP |
| net-s.pl | net-s.pl | Networking and VoIP |
| plantro.pl | plantro.pl | Headsets and IP phones |

### IT / Networking / Servers

| Shop | URL | Notes |
|------|-----|-------|
| Senetic.pl | senetic.pl | Servers, networking, licenses |
| ABI.pl | abi.pl | Servers, storage |
| wisp.pl | wisp.pl | Network equipment, distributor |
| soteris.pl | soteris.pl | Servers, NAS |
| servereach.pl | servereach.pl | Servers and infrastructure |

### Office / Furniture / Ergonomics

| Shop | URL | Notes |
|------|-----|-------|
| ergopoint.com.pl | ergopoint.com.pl | Ergonomic chairs |
| ajprodukty.pl | ajprodukty.pl | Office furniture |
| jysk.pl | jysk.pl | General furniture |
| nowy-styl.pl | nowy-styl.pl | Polish office furniture manufacturer |

### Tools / Power Tools

| Shop | URL | Notes |
|------|-----|-------|
| castorama.pl | castorama.pl | Home improvement |
| leroymerlin.pl | leroymerlin.pl | Home improvement |
| narzedziak.pl | narzedziak.pl | Specialist tools |

### Audio / Video / Photography

| Shop | URL | Notes |
|------|-----|-------|
| fotoforma.pl | fotoforma.pl | Photo and video |
| cyfrowe.pl | cyfrowe.pl | Photo, drones |
| muzyczny.pl | muzyczny.pl | Professional audio |

## B2B Portals / Distributors

For business purchases — net prices, wholesale terms.

| Portal | URL | Industry |
|--------|-----|----------|
| AB.pl | ab.pl | IT, electronics (distributor), official Apple PL distributor since 2011 |
| Action.pl | action.pl | IT (distributor) |
| Also.pl | also.pl | IT (distributor) |
| Incom Group | incomgroup.pl | Apple distributor, prices after registration |
| Innergo | innergo.store | Apple Premium Business Partner |
| Kontel.net | kontel.net | Yealink, video conferencing |
| Exclusive Networks | exclusive-networks.com/pl | Security, networking |

### B2B Search Patterns

```
"{PRODUCT}" dystrybutor Polska
"{BRAND}" importer Polska
"{BRAND}" autoryzowany reseller
"{PRODUCT}" site:ab.pl OR site:action.pl OR site:also.pl
```

## Shipping Providers — Typical Costs

| Service | Typical Cost | Notes |
|---------|-------------|-------|
| InPost Paczkomat | 12-16 PLN | Most popular, cheapest |
| InPost Courier | 12-18 PLN | |
| DPD | 15-20 PLN | |
| DHL | 15-22 PLN | |
| Poczta Polska | 12-18 PLN | Slower |
| Courier (general) | 15-25 PLN | |
| In-store pickup | 0 PLN | Not all shops |

### Free Shipping — Typical Thresholds

| Shop | Free Shipping Threshold |
|------|------------------------|
| Morele.net | From 399 PLN |
| Rozetka.pl | From 199 PLN |
| x-kom.pl | Often free |
| Media Expert | From 299 PLN |
| RTV Euro AGD | From 250 PLN |
| MediaMarkt.pl | Free |

## Search Patterns — Templates

### Price Discovery

```
site:ceneo.pl "{PRODUCT}"
"{PRODUCT}" cena kupić
"{PRODUCT}" sklep internetowy
"{PRODUCT}" porównanie cen
```

### Specialist Shop Discovery

```
"{PRODUCT}" sklep
"{CATEGORY} sklep internetowy Polska"
"{BRAND}" sklep autoryzowany
```

### Warranty

```
site:{SHOP} gwarancja regulamin
"{BRAND}" gwarancja producenta Polska
"{BRAND}" serwis autoryzowany Polska
"{BRAND}" dystrybutor importer Polska
```

### B2B

```
"{PRODUCT}" faktura VAT
"{PRODUCT}" hurtownia
"{BRAND}" dystrybutor B2B Polska
```

### Allegro — Seller Verification

```
site:allegro.pl "{PRODUCT}"
"{SELLER}" allegro opinie
"{BRAND}" autoryzowany sprzedawca allegro
```
