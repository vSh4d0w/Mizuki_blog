// 本地番剧数据配置
export type AnimeItem = {
	title: string;
	status: "watching" | "completed" | "planned";
	rating: number;
	cover: string;
	description: string;
	episodes: string;
	year: string;
	genre: string[];
	studio: string;
	link: string;
	progress: number;
	totalEpisodes: number;
	startDate: string;
	endDate: string;
};

// 这里是番剧数据列表，在此添加
const localAnimeList: AnimeItem[] = [
	{
		title: "Lycoris Recoil", // 标题
		status: "completed", // 观看状态 watching | completed | planned
		rating: 9.8, // 评分 (满分10)
		cover: "/assets/anime/lkls.webp", // 封面图片路径
		description: "Girl's gunfight", // 简介
		episodes: "12 episodes", // 集数
		year: "2022", // 年份
		genre: ["Action", "Slice of life"], // 类型
		studio: "A-1 Pictures", // 制作公司
		link: "https://www.bilibili.com/bangumi/media/md28338623", // 链接
		progress: 12, // 观看进度
		totalEpisodes: 12, // 总集数
		startDate: "2022-07", // 开始日期
		endDate: "2022-09", // 结束日期
	},
];

export default localAnimeList;
