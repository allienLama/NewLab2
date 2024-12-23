# NewLab2
# URL Status and Blacklist Checker

Bu layihə, `access_log.txt` faylından URL-ləri və HTTP status kodlarını çıxarır, 404 status kodu olan URL-ləri analiz edir, `threat_feed.html` faylında yerləşən qara siyahıya düşmüş domenləri alır və bu domenlərlə əlaqəli URL-ləri təhlil edir. Əgər URL-lər qara siyahıda varsa, bu URL-lər haqqında xəbərdarlıq JSON faylı yaradılır. 

## Tələblər

Bu layihə üçün aşağıdakı Python kitabxanaları tələb olunur:

- selenium==4.6.0
- webdriver-manager==3.8.0

## Quraşdırma

### 2. Virtual mühit yaratmaq



1. **Virtual mühit yaratmaq:**

   Layihə qovluğuna daxil olduqdan sonra aşağıdakı əmri işlədin:

   ```bash
   python -m venv venv

2. **Virtual mühiti aktivləşdirmək:**

   Windows : ```
   python -m venv venv```
   
   Mac/Linux: ```source venv/bin/activate```

### 2. Asılılıqları Quraşdırmaq

Virtual mühit aktiv olduqdan sonra, layihə üçün tələb olunan Python paketlərini quraşdırmaq lazımdır. Bunun üçün aşağıdakı əmri işlədin:

   ```bash
  pip install -r requirements.txt
```

### 3. Skripti İşə Salmaq
   ```bash
  python lab2.py

```



