// TeftişPro - Denetim Simülasyonu
// Her firma için 30 adet taslak (draft) denetim oluşturur
// Puan aralığı: %70 - %100

const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// -------------------------------------------------------------------
// Yardımcı fonksiyonlar
// -------------------------------------------------------------------

/** Random integer — inclusive her iki uç */
function randInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

/** Verilen gün sayısı kadar geçmişe/geleceğe giden rastgele tarih */
function randomDateInRange(daysBack, daysForward = 0) {
    const now = new Date();
    const offsetMs = (randInt(-daysBack, daysForward)) * 24 * 60 * 60 * 1000;
    return new Date(now.getTime() + offsetMs);
}

/**
 * Toplam puan ve maksimum puan verildiğinde %70-%100 aralığına
 * sığan cevap değerlerini üretir.
 *
 * Değer kodları:
 *   U  (Uygun)           → tam puan
 *   YP (Yarı Puanlı)     → yarım puan
 *   UD (Uygun Değil)     → sıfır puan
 *   DD (Değerlendirme D.)→ hesaba katılmaz (sıfır puan, maxPuan azalır)
 *
 * Hedef: earned / maxTotal ∈ [0.70, 1.00]
 */
function buildAnswers(questions) {
    // Kaç soruya DD vereceğimize karar ver (%0-%10 arası rastgele)
    const ddCount = randInt(0, Math.floor(questions.length * 0.1));
    const shuffled = [...questions].sort(() => Math.random() - 0.5);
    const ddSet = new Set(shuffled.slice(0, ddCount).map(q => q.id));

    // Geçerli sorular ve max puan
    const activeQuestions = questions.filter(q => !ddSet.has(q.id));
    const maxTotal = activeQuestions.reduce((s, q) => s + q.points, 0);

    // Hedef kazanılan puan → %70-%100 bandı
    const targetRatio = (randInt(700, 1000)) / 1000; // 0.700 – 1.000
    const targetPoints = Math.round(maxTotal * targetRatio);

    // Greedy dağıtım: U → tam, YP → yarım, UD → sıfır
    // Önce herkesi U yap, sonra düşür
    const values = new Map(activeQuestions.map(q => [q.id, 'U']));
    let earned = maxTotal;

    // Fazlayı düşür
    let excess = earned - targetPoints;

    // Rastgele sırayla UD veya YP koy
    const activeShuffled = [...activeQuestions].sort(() => Math.random() - 0.5);

    for (const q of activeShuffled) {
        if (excess <= 0) break;

        if (excess >= q.points) {
            // Tam UD
            values.set(q.id, 'UD');
            excess -= q.points;
            earned -= q.points;
        } else if (excess >= Math.ceil(q.points / 2)) {
            // YP (yarım puan)
            values.set(q.id, 'YP');
            const halfPoints = Math.ceil(q.points / 2);
            excess -= (q.points - halfPoints); // YP kazandırdığı
            earned -= (q.points - halfPoints);
        }
    }

    // Cevap nesneleri oluştur
    return questions.map(q => ({
        questionId: q.id,
        value: ddSet.has(q.id) ? 'DD' : (values.get(q.id) ?? 'U'),
        note: (values.get(q.id) === 'UD' || values.get(q.id) === 'YP')
            ? 'Simülasyon notu: Eksiklik tespit edilmiştir.'
            : null
    }));
}

// -------------------------------------------------------------------
// Ana fonksiyon
// -------------------------------------------------------------------

async function main() {
    console.log('🚀 Denetim simülasyonu başlatılıyor...\n');

    // ---  Mevcut soruları çek  ---
    const allQuestions = await prisma.question.findMany({
        select: { id: true, points: true, categoryId: true }
    });

    if (allQuestions.length === 0) {
        console.error('❌ Veritabanında hiç soru bulunamadı. Önce seed.js çalıştırın.');
        process.exit(1);
    }
    console.log(`📋 Toplam ${allQuestions.length} soru bulundu.\n`);

    // ---  Saha denetçisini bul (field rolü)  ---
    const fieldUser = await prisma.user.findFirst({
        where: { role: { name: 'field' } }
    });
    // Admin de denetçi olarak kullanılabilir (yedek)
    const adminUser = await prisma.user.findFirst({
        where: { role: { name: 'admin' } }
    });

    if (!fieldUser && !adminUser) {
        console.error('❌ Denetçi kullanıcı bulunamadı.');
        process.exit(1);
    }

    const auditorId = (fieldUser ?? adminUser).id;
    console.log(`👤 Denetçi: ${(fieldUser ?? adminUser).name} (${(fieldUser ?? adminUser).email})\n`);

    // ---  Firma konfigürasyonları  ---
    const firmaConfigs = [
        {
            companyName: 'HD İskender',
            branchFilter: { name: 'HD İskender Şube' }
        },
        {
            companyName: 'Demo Holding A.Ş.',
            branchFilter: { name: { in: ['Kadıköy Şubesi', 'Beşiktaş Şubesi', 'Bursa Merkez Şubesi'] } }
        }
    ];

    const AUDIT_COUNT = 30; // Her firma için

    // Denetim başlık havuzu
    const titleTemplates = [
        'Rutin Aylık Denetim',
        'Yangın Güvenliği Denetimi',
        'Genel Hijyen Kontrolü',
        'ISG Uyum Denetimi',
        'Müşteri Deneyimi Değerlendirmesi',
        'Stok ve Depo Denetimi',
        'Periyodik Kalite Kontrolü',
        'Operasyonel Denetim',
        'Standart Uyum Kontrolü',
        'Yönetim Sistemi Denetimi'
    ];

    const yetkiliKisiler = [
        'Serkan Doğan', 'Elif Çelik', 'Burak Şahin', 'Neslihan Yıldız',
        'Kerem Arslan', 'Seda Kurt', 'Oğuz Yılmaz', 'Berna Aydın',
        'Tarık Öztürk', 'Melis Kaya'
    ];

    // ---  Her firma için denetim oluştur  ---
    for (const config of firmaConfigs) {
        const company = await prisma.company.findUnique({
            where: { name: config.companyName }
        });

        if (!company) {
            console.warn(`⚠️  "${config.companyName}" şirketi bulunamadı, atlanıyor.`);
            continue;
        }

        const branches = await prisma.branch.findMany({
            where: { companyId: company.id, ...config.branchFilter }
        });

        if (branches.length === 0) {
            console.warn(`⚠️  "${config.companyName}" için şube bulunamadı, atlanıyor.`);
            continue;
        }

        console.log(`\n🏢 ${config.companyName} — ${AUDIT_COUNT} denetim oluşturuluyor...`);

        let created = 0;

        for (let i = 0; i < AUDIT_COUNT; i++) {
            // Şubeyi döngüsel seç
            const branch = branches[i % branches.length];

            // Rastgele taslak tarihi (son 6 ay içinde başladı)
            const scheduledDate = randomDateInRange(180, 0);
            const startedAt = new Date(scheduledDate.getTime() + randInt(1, 120) * 60000); // 1-120 dk sonra

            // Cevapları oluştur
            const answerData = buildAnswers(allQuestions);

            // Denetimi oluştur
            const audit = await prisma.audit.create({
                data: {
                    userId: auditorId,
                    companyId: company.id,
                    branchId: branch.id,
                    status: 'draft',
                    title: `${titleTemplates[i % titleTemplates.length]} #${i + 1}`,
                    authorizedPerson: yetkiliKisiler[i % yetkiliKisiler.length],
                    scheduledDate,
                    startedAt,
                    // Gönderilmedi → submittedAt null kalır
                    answers: {
                        create: answerData
                    }
                }
            });

            created++;

            // İlerleme göster
            process.stdout.write(
                `\r  ✍️  Oluşturulan: ${created}/${AUDIT_COUNT} — Şube: ${branch.name.padEnd(25)} — Durum: draft`
            );
        }

        console.log(`\n✅ ${config.companyName}: ${created} denetim başarıyla oluşturuldu.`);
    }

    console.log('\n\n🎉 Denetim simülasyonu tamamlandı!');
    console.log('\n📊 Özet:');
    console.log(`  • HD İskender       → ${AUDIT_COUNT} draft denetim`);
    console.log(`  • Demo Holding A.Ş. → ${AUDIT_COUNT} draft denetim`);
    console.log(`  • Toplam            → ${AUDIT_COUNT * 2} denetim`);
    console.log('\n  Tüm denetimler "draft" (taslak) durumundadır.');
    console.log('  Puan aralığı: %70 – %100');
}

// -------------------------------------------------------------------
// Çalıştır
// -------------------------------------------------------------------
main()
    .catch((e) => {
        console.error('\n❌ Simülasyon hatası:', e);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });
